package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	helperProtocolVersion = "8-root-tproxy"
	defaultListenAddr     = "127.0.0.1:47890"
	defaultPackageName    = "com.kestrel.netstat.app"
	defaultTProxyPort     = 7893
	defaultDnsPort        = 1053
	// Use bits 24..27 so Android netd's low 24-bit network marks and bit 31 flags stay intact.
	tproxyMarkHexMask = "0x08000000/0x0f000000"
	bypassMarkHexMask = "0x09000000/0x0f000000" // decimal routing-mark: 150994944
	routeTableID      = "233"
	coreReadyTimeout  = 5 * time.Second
	coreStopTimeout   = 4 * time.Second
)

type Config struct {
	ListenAddr   string
	CoreBin      string
	PackageName  string
	TProxyPort   int
	DnsPort      int
	EnableIPv6   bool
	CoreLogFile  string
}

type ManagedCore struct {
	PID             int
	CoreAddr        string
	CoreToken       string
	StartedAtMillis int64
	Cmd             *exec.Cmd
	Done            chan struct{}
}

type HelperServer struct {
	cfg             Config
	mu              sync.Mutex
	core            *ManagedCore
	tproxyActive    bool
	tproxyPort      int
	dnsPort         int
	dnsHijack       bool
	enableIPv6      bool
	tproxyStartTime int64

	uidMu     sync.Mutex
	cachedUID int
	uidLoaded bool

	region *RegionManager
}

type statusResponse struct {
	CoreRunning     bool   `json:"coreRunning"`
	TProxyActive    bool   `json:"tproxyActive"`
	PID             int    `json:"pid,omitempty"`
	CoreAddr        string `json:"coreAddr,omitempty"`
	CoreToken       string `json:"coreToken,omitempty"`
	TProxyPort      int    `json:"tproxyPort,omitempty"`
	StartedAtMillis int64  `json:"startedAtMillis,omitempty"`
}

type tproxyStartRequest struct {
	TProxyPort int   `json:"tproxyPort,omitempty"`
	DnsPort    int   `json:"dnsPort,omitempty"`
	MixedPort  int   `json:"mixedPort,omitempty"`
	DnsHijack  *bool `json:"dnsHijack,omitempty"`
	EnableIPv6 *bool `json:"enableIPv6,omitempty"`
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.ListenAddr, "listen", defaultListenAddr, "helper HTTP listen address")
	flag.StringVar(&cfg.CoreBin, "core", "/data/adb/modules/flclash_tproxy/bin/FlClashCore", "path to FlClashCore binary")
	flag.StringVar(&cfg.PackageName, "pkg", defaultPackageName, "authorized Android package name")
	flag.IntVar(&cfg.TProxyPort, "tproxy-port", defaultTProxyPort, "default mihomo tproxy-port")
	flag.IntVar(&cfg.DnsPort, "dns-port", defaultDnsPort, "default mihomo dns.listen port")
	flag.BoolVar(&cfg.EnableIPv6, "ipv6", false, "enable ip6tables TProxy rules")
	flag.StringVar(&cfg.CoreLogFile, "core-log", "/data/adb/flclash-tproxy/core.log", "core stderr log path")
	flag.Parse()

	srv := &HelperServer{
		cfg:        cfg,
		tproxyPort: cfg.TProxyPort,
		dnsPort:    cfg.DnsPort,
		dnsHijack:  true,
		enableIPv6: cfg.EnableIPv6,
		region:     newRegionManager(filepath.Dir(cfg.CoreLogFile)),
	}
	srv.region.init()
	ensureGmsAndAppUnfrozen(cfg.PackageName)
	srv.startTProxyWatchdog()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", srv.requireCallerUID(srv.handlePing))
	mux.HandleFunc("/status", srv.requireCallerUID(srv.handleStatus))
	mux.HandleFunc("/core/ensure", srv.requireCallerUID(srv.handleCoreEnsure))
	mux.HandleFunc("/core/stop", srv.requireCallerUID(srv.handleCoreStop))
	mux.HandleFunc("/tproxy/start", srv.requireCallerUID(srv.handleTProxyStart))
	mux.HandleFunc("/tproxy/stop", srv.requireCallerUID(srv.handleTProxyStop))
	mux.HandleFunc("/region/status", srv.requireCallerUID(srv.handleRegionStatus))
	mux.HandleFunc("/region/config", srv.requireCallerUID(srv.handleRegionConfig))
	mux.HandleFunc("/region/apply", srv.requireCallerUID(srv.handleRegionApply))
	mux.HandleFunc("/region/sync", srv.requireCallerUID(srv.handleRegionSync))
	mux.HandleFunc("/region/restore", srv.requireCallerUID(srv.handleRegionRestore))

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("signal received, cleaning up tproxy & core...")
		srv.shutdownAll()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	log.Printf("flclash-helper listening on %s (pkg=%s core=%s)", cfg.ListenAddr, cfg.PackageName, cfg.CoreBin)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		srv.shutdownAll()
		log.Fatalf("listen error: %v", err)
	}
}

// requireCallerUID enforces kernel-level socket ownership via /proc/net/tcp so
// only the target FlClash APK UID or root (UID 0) can control the daemon.
func (s *HelperServer) requireCallerUID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := lookupLoopbackPeerUID(r.RemoteAddr, s.cfg.ListenAddr)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"code":    "peer_uid_unknown",
				"message": err.Error(),
			})
			return
		}
		if uid != 0 {
			appUID, err := s.resolvePackageUID()
			if err != nil || uid != appUID {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"code":    "forbidden_uid",
					"message": fmt.Sprintf("caller uid %d not authorized", uid),
				})
				return
			}
		}
		next(w, r)
	}
}

func (s *HelperServer) resolvePackageUID() (int, error) {
	s.uidMu.Lock()
	defer s.uidMu.Unlock()
	if s.uidLoaded && s.cachedUID > 0 {
		return s.cachedUID, nil
	}
	f, err := os.Open("/data/system/packages.list")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prefix := s.cfg.PackageName + " "
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == s.cfg.PackageName {
			uid, convErr := strconv.Atoi(fields[1])
			if convErr == nil && uid > 0 {
				s.cachedUID = uid
				s.uidLoaded = true
				return uid, nil
			}
		}
	}
	return 0, fmt.Errorf("package %s not found", s.cfg.PackageName)
}

func lookupLoopbackPeerUID(remoteAddr, listenAddr string) (int, error) {
	rHost, rPortStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return -1, err
	}
	_, lPortStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return -1, err
	}
	if rHost != "127.0.0.1" && rHost != "::1" {
		return -1, errors.New("non-loopback peer")
	}
	rPort, err := strconv.Atoi(rPortStr)
	if err != nil {
		return -1, err
	}
	lPort, err := strconv.Atoi(lPortStr)
	if err != nil {
		return -1, err
	}

	wantLocal4 := fmt.Sprintf("0100007F:%04X", rPort)
	wantRemote4 := fmt.Sprintf("0100007F:%04X", lPort)
	if uid, ok := scanProcNet("/proc/net/tcp", wantLocal4, wantRemote4); ok {
		return uid, nil
	}
	wantLocal6 := fmt.Sprintf("00000000000000000000000001000000:%04X", rPort)
	wantRemote6 := fmt.Sprintf("00000000000000000000000001000000:%04X", lPort)
	if uid, ok := scanProcNet("/proc/net/tcp6", wantLocal6, wantRemote6); ok {
		return uid, nil
	}
	wantLocalV4M := fmt.Sprintf("0000000000000000FFFF00000100007F:%04X", rPort)
	wantRemoteV4M := fmt.Sprintf("0000000000000000FFFF00000100007F:%04X", lPort)
	if uid, ok := scanProcNet("/proc/net/tcp6", wantLocalV4M, wantRemoteV4M); ok {
		return uid, nil
	}
	return -1, errors.New("peer socket not found in /proc/net/tcp")
}

func scanProcNet(path, localHex, remoteHex string) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return -1, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		if strings.EqualFold(fields[1], localHex) && strings.EqualFold(fields[2], remoteHex) {
			uid, err := strconv.Atoi(fields[7])
			if err == nil {
				return uid, true
			}
		}
	}
	return -1, false
}

func (s *HelperServer) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	coreRunning := s.core != nil
	tproxyActive := s.tproxyActive
	s.mu.Unlock()

	w.Header().Set("x-flclash-helper-protocol", helperProtocolVersion)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"coreRunning":  coreRunning,
		"tproxyActive": tproxyActive,
		"coreBin":      s.cfg.CoreBin,
	})
}

func (s *HelperServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.statusLocked())
}

func (s *HelperServer) statusLocked() statusResponse {
	if s.core == nil {
		return statusResponse{
			CoreRunning:  false,
			TProxyActive: s.tproxyActive,
			TProxyPort:   s.tproxyPort,
		}
	}
	return statusResponse{
		CoreRunning:     true,
		TProxyActive:    s.tproxyActive,
		PID:             s.core.PID,
		CoreAddr:        s.core.CoreAddr,
		CoreToken:       s.core.CoreToken,
		TProxyPort:      s.tproxyPort,
		StartedAtMillis: s.tproxyStartTime,
	}
}

func (s *HelperServer) handleCoreEnsure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.core != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"pid":             s.core.PID,
			"coreAddr":        s.core.CoreAddr,
			"coreToken":       s.core.CoreToken,
			"startedAtMillis": s.core.StartedAtMillis,
			"reused":          true,
		})
		return
	}

	m, err := s.spawnCoreLocked()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"code":    "processLaunchFailed",
			"message": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid":             m.PID,
		"coreAddr":        m.CoreAddr,
		"coreToken":       m.CoreToken,
		"startedAtMillis": m.StartedAtMillis,
		"reused":          false,
	})
}

func (s *HelperServer) handleCoreStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hadCore := s.core != nil
	s.stopAllLocked()
	writeJSON(w, http.StatusOK, map[string]any{
		"stopped": hadCore,
	})
}

func (s *HelperServer) handleTProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req tproxyStartRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.core == nil {
		if _, err := s.spawnCoreLocked(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"code":    "processLaunchFailed",
				"message": err.Error(),
			})
			return
		}
	}

	port := req.TProxyPort
	if port <= 0 || port > 65535 {
		port = s.cfg.TProxyPort
	}
	dnsPort := req.DnsPort
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = s.cfg.DnsPort
	}
	dnsHijack := true
	if req.DnsHijack != nil {
		dnsHijack = *req.DnsHijack
	}
	enableIPv6 := s.cfg.EnableIPv6
	if req.EnableIPv6 != nil {
		enableIPv6 = *req.EnableIPv6
	}

	if s.tproxyActive && s.tproxyPort == port && s.dnsPort == dnsPort && s.dnsHijack == dnsHijack && s.enableIPv6 == enableIPv6 {
		writeJSON(w, http.StatusOK, s.statusLocked())
		return
	}

	if err := setupTProxy(port, dnsPort, dnsHijack, enableIPv6); err != nil {
		_ = teardownTProxy()
		s.tproxyActive = false
		s.tproxyStartTime = 0
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"code":    "tproxy_failed",
			"message": err.Error(),
		})
		return
	}
	s.tproxyActive = true
	s.tproxyPort = port
	s.dnsPort = dnsPort
	s.dnsHijack = dnsHijack
	s.enableIPv6 = enableIPv6
	if s.tproxyStartTime == 0 {
		s.tproxyStartTime = time.Now().UnixMilli()
	}
	mixedPort := req.MixedPort
	if mixedPort <= 0 || mixedPort > 65535 {
		mixedPort = 7890
	}
	s.region.onTProxyStarted(mixedPort)
	writeJSON(w, http.StatusOK, s.statusLocked())
}

func (s *HelperServer) handleTProxyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = teardownTProxy()
	s.tproxyActive = false
	s.tproxyStartTime = 0
	s.region.onTProxyStopped()
	writeJSON(w, http.StatusOK, s.statusLocked())
}

func (s *HelperServer) spawnCoreLocked() (*ManagedCore, error) {
	if _, err := os.Stat(s.cfg.CoreBin); err != nil {
		return nil, fmt.Errorf("core binary unavailable: %w", err)
	}
	coreAddr, err := pickFreeLoopbackAddr()
	if err != nil {
		return nil, err
	}
	coreToken, err := randomHex(32)
	if err != nil {
		return nil, err
	}

	var logOut io.Writer = io.Discard
	if s.cfg.CoreLogFile != "" {
		_ = os.MkdirAll(filepath.Dir(s.cfg.CoreLogFile), 0o755)
		if f, openErr := os.OpenFile(s.cfg.CoreLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); openErr == nil {
			logOut = f
		}
	}

	tmpDir := "/data/adb/flclash-tproxy/tmp"
	_ = os.MkdirAll(tmpDir, 0o700)
	sslCertDir := "/apex/com.android.conscrypt/cacerts"
	if _, err := os.Stat(sslCertDir); err != nil {
		sslCertDir = "/system/etc/security/cacerts"
	}

	cmd := exec.Command(s.cfg.CoreBin, "-daemon", coreAddr)
	cmd.Env = append(os.Environ(),
		"FLCLASH_CORE_TOKEN="+coreToken,
		"TMPDIR="+tmpDir,
		"SSL_CERT_DIR="+sslCertDir,
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = logOut
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	managed := &ManagedCore{
		PID:             cmd.Process.Pid,
		CoreAddr:        coreAddr,
		CoreToken:       coreToken,
		StartedAtMillis: time.Now().UnixMilli(),
		Cmd:             cmd,
		Done:            make(chan struct{}),
	}

	go func() {
		err := cmd.Wait()
		close(managed.Done)
		log.Printf("core pid=%d exited: %v", managed.PID, err)
		s.mu.Lock()
		if s.core == managed {
			s.core = nil
			if s.tproxyActive {
				_ = teardownTProxy()
				s.tproxyActive = false
				s.tproxyStartTime = 0
				s.region.onTProxyStopped()
			}
		}
		s.mu.Unlock()
	}()

	if err := waitTCPReady(coreAddr, managed.Done, coreReadyTimeout); err != nil {
		s.killCore(managed)
		return nil, err
	}
	s.core = managed
	return managed, nil
}

func (s *HelperServer) stopAllLocked() {
	if s.tproxyActive {
		_ = teardownTProxy()
		s.tproxyActive = false
		s.tproxyStartTime = 0
		s.region.onTProxyStopped()
	}
	if s.core != nil {
		s.killCore(s.core)
		s.core = nil
	}
}

func (s *HelperServer) killCore(m *ManagedCore) {
	if m == nil || m.Cmd == nil || m.Cmd.Process == nil {
		return
	}
	_ = m.Cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-m.Done:
	case <-time.After(coreStopTimeout):
		_ = m.Cmd.Process.Kill()
		<-m.Done
	}
}

func (s *HelperServer) shutdownAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopAllLocked()
}

// ---------------- TProxy Policy Routing & iptables ----------------

var ipv4BypassCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

func collectDynamicBypassIPs(wantV6 bool) []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			if wantV6 {
				continue
			}
			cidr := v4.String() + "/32"
			if _, exists := seen[cidr]; !exists {
				seen[cidr] = struct{}{}
				out = append(out, cidr)
			}
		} else if wantV6 {
			cidr := ipNet.IP.String() + "/128"
			if _, exists := seen[cidr]; !exists {
				seen[cidr] = struct{}{}
				out = append(out, cidr)
			}
		}
	}
	return out
}

func setupTProxy(port int, dnsPort int, dnsHijack bool, enableIPv6 bool) error {
	_ = teardownTProxy()

	// Loose reverse-path filtering (rp_filter=2) required for TPROXY on Android multi-interface routing.
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("2"), 0o644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("2"), 0o644)

	if err := runCmd("ip", "rule", "add", "fwmark", tproxyMarkHexMask, "table", routeTableID, "pref", "100"); err != nil {
		return fmt.Errorf("ip rule add: %w", err)
	}
	if err := runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", routeTableID); err != nil {
		return fmt.Errorf("ip route add: %w", err)
	}

	pStr := strconv.Itoa(port)
	bypassV4 := append(append([]string{}, ipv4BypassCIDRs...), collectDynamicBypassIPs(false)...)
	tproxyPreIfaces := []string{"lo", "wlan1", "ap+", "rndis+"}

	cmds := [][]string{
		{"iptables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_PRE"},
		{"iptables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_OUT"},
		{"iptables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_DIVERT"},
		{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_DIVERT", "-j", "MARK", "--set-xmark", tproxyMarkHexMask},
		{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_DIVERT", "-j", "ACCEPT"},
	}

	for _, cidr := range bypassV4 {
		cmds = append(cmds, []string{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_PRE", "-d", cidr, "-j", "RETURN"})
	}
	for _, iface := range tproxyPreIfaces {
		for _, proto := range []string{"tcp", "udp"} {
			cmds = append(cmds, []string{
				"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_PRE",
				"-i", iface, "-p", proto,
				"-j", "TPROXY", "--on-ip", "127.0.0.1", "--on-port", pStr, "--tproxy-mark", tproxyMarkHexMask,
			})
		}
	}

	// OUTPUT: let loopback, mihomo's marked sockets, and redirected :53 DNS bypass TProxy mangle mark.
	cmds = append(cmds,
		[]string{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT", "-o", "lo", "-j", "RETURN"},
		[]string{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT", "-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	)
	if dnsHijack && dnsPort > 0 {
		for _, proto := range []string{"tcp", "udp"} {
			cmds = append(cmds, []string{
				"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT",
				"-p", proto, "--dport", "53", "-j", "RETURN",
			})
		}
	}
	for _, cidr := range bypassV4 {
		cmds = append(cmds, []string{"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT", "-d", cidr, "-j", "RETURN"})
	}
	for _, proto := range []string{"tcp", "udp"} {
		cmds = append(cmds, []string{
			"iptables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT",
			"-p", proto,
			"-j", "MARK", "--set-xmark", tproxyMarkHexMask,
		})
	}

	cmds = append(cmds,
		[]string{"iptables", "-w", "2", "-t", "mangle", "-A", "PREROUTING", "-j", "FLCLASH_PRE"},
		[]string{"iptables", "-w", "2", "-t", "mangle", "-A", "OUTPUT", "-j", "FLCLASH_OUT"},
	)

	// IPv4 DNS redirect into mihomo's dns.listen (rule #1 in nat OUTPUT overrides AdGuardHome while active),
	// Fake-IP ICMP ping DNAT to 127.0.0.1, plus reject non-core DoT (:853) and core loopback TProxy self-access.
	if dnsHijack && dnsPort > 0 {
		dnsStr := strconv.Itoa(dnsPort)
		cmds = append(cmds,
			[]string{"iptables", "-w", "2", "-t", "nat", "-N", "FLCLASH_DNS"},
			[]string{"iptables", "-w", "2", "-t", "nat", "-A", "FLCLASH_DNS", "-m", "mark", "--mark", bypassMarkHexMask, "-j", "ACCEPT"},
			[]string{"iptables", "-w", "2", "-t", "nat", "-A", "FLCLASH_DNS", "-d", "198.18.0.0/16", "-p", "icmp", "-j", "DNAT", "--to-destination", "127.0.0.1"},
			[]string{"iptables", "-w", "2", "-t", "nat", "-A", "FLCLASH_DNS", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsStr},
			[]string{"iptables", "-w", "2", "-t", "nat", "-A", "FLCLASH_DNS", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsStr},
			[]string{"iptables", "-w", "2", "-t", "nat", "-I", "OUTPUT", "1", "-j", "FLCLASH_DNS"},
			[]string{"iptables", "-w", "2", "-t", "nat", "-I", "PREROUTING", "1", "-j", "FLCLASH_DNS"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-N", "FLCLASH_DOT"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-A", "FLCLASH_DOT", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "mark", "--mark", bypassMarkHexMask, "--dport", pStr, "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-A", "FLCLASH_DOT", "-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-A", "FLCLASH_DOT", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-A", "FLCLASH_DOT", "-p", "udp", "--dport", "853", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			[]string{"iptables", "-w", "2", "-t", "filter", "-I", "OUTPUT", "1", "-j", "FLCLASH_DOT"},
		)
	}

	// IPv6 leak guard: block global IPv6 egress when IPv6 is disabled (preserving ::1, fe80::/10, ff00::/8 for VoLTE/NDP);
	// when IPv6 TProxy is enabled, still reject non-core IPv6 DNS (:53/:853) because Android kernels lack ip6table_nat.
	cmds = append(cmds,
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-N", "FLCLASH_V6_BLOCK"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-o", "lo", "-j", "RETURN"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-d", "::1/128", "-j", "RETURN"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-d", "fe80::/10", "-j", "RETURN"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-d", "ff00::/8", "-j", "RETURN"},
	)
	if enableIPv6 {
		cmds = append(cmds,
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-p", "tcp", "--dport", "53", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-p", "udp", "--dport", "53", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"},
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-p", "udp", "--dport", "853", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"},
		)
	} else {
		cmds = append(cmds,
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"ip6tables", "-w", "2", "-t", "filter", "-A", "FLCLASH_V6_BLOCK", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"},
		)
	}
	cmds = append(cmds,
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-I", "OUTPUT", "1", "-j", "FLCLASH_V6_BLOCK"},
		[]string{"ip6tables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-j", "FLCLASH_V6_BLOCK"},
	)

	for _, c := range cmds {
		if err := runCmd(c[0], c[1:]...); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(c, " "), err)
		}
	}

	// Best-effort kernel optimizations: DIVERT for established transparent sockets + conntrack REPLY bypass.
	_ = exec.Command("iptables", "-w", "2", "-t", "mangle", "-I", "PREROUTING", "1", "-p", "tcp", "-m", "socket", "--transparent", "-j", "FLCLASH_DIVERT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "mangle", "-I", "FLCLASH_PRE", "1", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "mangle", "-I", "FLCLASH_OUT", "1", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN").Run()

	if enableIPv6 {
		setWlanIPv6Disabled(false)
		if err := setupTProxyV6(pStr); err != nil {
			return err
		}
	} else {
		setWlanIPv6Disabled(true)
	}
	setupFirewallBypassRules()
	ensureGmsAndAppUnfrozen("")
	return nil
}

type firewallRule struct {
	bin   string
	chain string
	args  []string
}

var (
	v4OutputBypassSpecs = [][]string{
		{"-o", "lo", "-j", "RETURN"},
		{"-d", "127.0.0.0/8", "-j", "RETURN"},
		{"-m", "mark", "--mark", tproxyMarkHexMask, "-j", "RETURN"},
		{"-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	}
	v4InputBypassSpecs = [][]string{
		{"-i", "lo", "-j", "RETURN"},
		{"-s", "127.0.0.0/8", "-j", "RETURN"},
		{"-m", "mark", "--mark", tproxyMarkHexMask, "-j", "RETURN"},
		{"-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	}
	v6OutputBypassSpecs = [][]string{
		{"-o", "lo", "-j", "RETURN"},
		{"-d", "::1/128", "-j", "RETURN"},
		{"-m", "mark", "--mark", tproxyMarkHexMask, "-j", "RETURN"},
		{"-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	}
	v6InputBypassSpecs = [][]string{
		{"-i", "lo", "-j", "RETURN"},
		{"-s", "::1/128", "-j", "RETURN"},
		{"-m", "mark", "--mark", tproxyMarkHexMask, "-j", "RETURN"},
		{"-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	}
)

func collectFirewallBypassRules() []firewallRule {
	var rules []firewallRule
	for _, chain := range []string{"fw_OUTPUT", "oplus_fw_OUTPUT"} {
		for _, spec := range v4OutputBypassSpecs {
			rules = append(rules, firewallRule{bin: "iptables", chain: chain, args: spec})
		}
		for _, spec := range v6OutputBypassSpecs {
			rules = append(rules, firewallRule{bin: "ip6tables", chain: chain, args: spec})
		}
	}
	for _, chain := range []string{"fw_INPUT", "oplus_fw_INPUT"} {
		for _, spec := range v4InputBypassSpecs {
			rules = append(rules, firewallRule{bin: "iptables", chain: chain, args: spec})
		}
		for _, spec := range v6InputBypassSpecs {
			rules = append(rules, firewallRule{bin: "ip6tables", chain: chain, args: spec})
		}
	}
	return rules
}

// ensureRuleFirst inserts a filter rule at position 1 only if it is not already present.
func ensureRuleFirst(bin, chain string, ruleArgs []string) {
	checkArgs := append([]string{"-w", "2", "-t", "filter", "-C", chain}, ruleArgs...)
	if exec.Command(bin, checkArgs...).Run() == nil {
		return
	}
	insertArgs := append([]string{"-w", "2", "-t", "filter", "-I", chain, "1"}, ruleArgs...)
	_ = exec.Command(bin, insertArgs...).Run()
}

// setupFirewallBypassRules prevents OEM eBPF chains (e.g. ColorOS fw_OUTPUT/oplus_fw_OUTPUT)
// from dropping redirected :53 DNS, TProxy-marked packets, or loopback delivery.
func setupFirewallBypassRules() {
	for _, r := range collectFirewallBypassRules() {
		ensureRuleFirst(r.bin, r.chain, r.args)
	}
}

func teardownFirewallBypassRules() {
	for _, r := range collectFirewallBypassRules() {
		delArgs := append([]string{"-w", "2", "-t", "filter", "-D", r.chain}, r.args...)
		for i := 0; i < 4; i++ {
			if exec.Command(r.bin, delArgs...).Run() != nil {
				break
			}
		}
	}
}

func ensureGmsAndAppUnfrozen(extraPkg string) {
	pkgs := []string{
		defaultPackageName,
		"com.google.android.gms",
		"com.android.vending",
		"com.google.android.gsf",
	}
	if extraPkg != "" && extraPkg != defaultPackageName {
		pkgs = append(pkgs, extraPkg)
	}
	for _, pkg := range pkgs {
		_ = exec.Command("cmd", "deviceidle", "whitelist", "+"+pkg).Run()
	}

	out, err := exec.Command("settings", "get", "secure", "no_frozen").Output()
	if err != nil {
		return
	}
	cur := strings.TrimSpace(string(out))
	if cur == "" || cur == "null" {
		return
	}
	existing := make(map[string]struct{})
	for _, item := range strings.Split(cur, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			existing[item] = struct{}{}
		}
	}
	changed := false
	for _, pkg := range pkgs {
		if _, ok := existing[pkg]; !ok {
			if !strings.HasSuffix(cur, ",") {
				cur += ","
			}
			cur += pkg + ","
			existing[pkg] = struct{}{}
			changed = true
		}
	}
	if changed {
		_ = exec.Command("settings", "put", "secure", "no_frozen", cur).Run()
	}
}

func (s *HelperServer) ensureTProxyRules() {
	s.mu.Lock()
	active := s.tproxyActive
	dnsHijack := s.dnsHijack
	dnsPort := s.dnsPort
	s.mu.Unlock()
	if !active {
		return
	}
	setupFirewallBypassRules()
	if dnsHijack && dnsPort > 0 {
		if exec.Command("iptables", "-w", "2", "-t", "nat", "-C", "OUTPUT", "-j", "FLCLASH_DNS").Run() != nil {
			_ = exec.Command("iptables", "-w", "2", "-t", "nat", "-I", "OUTPUT", "1", "-j", "FLCLASH_DNS").Run()
		}
	}
}

func (s *HelperServer) startTProxyWatchdog() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			s.ensureTProxyRules()
		}
	}()
}

func setWlanIPv6Disabled(disabled bool) {
	val := "0"
	if disabled {
		val = "1"
	}
	for _, iface := range []string{"wlan0", "wlan1"} {
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+iface+"/disable_ipv6", []byte(val), 0o644)
	}
}

func setupTProxyV6(pStr string) error {
	if err := runCmd("ip", "-6", "rule", "add", "fwmark", tproxyMarkHexMask, "table", routeTableID, "pref", "100"); err != nil {
		return fmt.Errorf("ip -6 rule add: %w", err)
	}
	if err := runCmd("ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", routeTableID); err != nil {
		return fmt.Errorf("ip -6 route add: %w", err)
	}
	v6Bypass := append([]string{"::1/128", "fe80::/10", "fc00::/7", "ff00::/8"}, collectDynamicBypassIPs(true)...)
	tproxyPreIfaces := []string{"lo", "wlan1", "ap+", "rndis+"}
	cmds := [][]string{
		{"ip6tables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_PRE6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_OUT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-N", "FLCLASH_DIVERT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_DIVERT6", "-j", "MARK", "--set-xmark", tproxyMarkHexMask},
		{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_DIVERT6", "-j", "ACCEPT"},
	}
	for _, cidr := range v6Bypass {
		cmds = append(cmds, []string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_PRE6", "-d", cidr, "-j", "RETURN"})
	}
	for _, iface := range tproxyPreIfaces {
		for _, proto := range []string{"tcp", "udp"} {
			cmds = append(cmds, []string{
				"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_PRE6",
				"-i", iface, "-p", proto, "-j", "TPROXY", "--on-ip", "::1", "--on-port", pStr, "--tproxy-mark", tproxyMarkHexMask,
			})
		}
	}
	cmds = append(cmds,
		[]string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT6", "-o", "lo", "-j", "RETURN"},
		[]string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT6", "-m", "mark", "--mark", bypassMarkHexMask, "-j", "RETURN"},
	)
	for _, cidr := range v6Bypass {
		cmds = append(cmds, []string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT6", "-d", cidr, "-j", "RETURN"})
	}
	for _, proto := range []string{"tcp", "udp"} {
		cmds = append(cmds, []string{
			"ip6tables", "-w", "2", "-t", "mangle", "-A", "FLCLASH_OUT6",
			"-p", proto, "-j", "MARK", "--set-xmark", tproxyMarkHexMask,
		})
	}
	cmds = append(cmds,
		[]string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "PREROUTING", "-j", "FLCLASH_PRE6"},
		[]string{"ip6tables", "-w", "2", "-t", "mangle", "-A", "OUTPUT", "-j", "FLCLASH_OUT6"},
	)
	for _, c := range cmds {
		if err := runCmd(c[0], c[1:]...); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(c, " "), err)
		}
	}
	_ = exec.Command("ip6tables", "-w", "2", "-t", "mangle", "-I", "PREROUTING", "1", "-p", "tcp", "-m", "socket", "--transparent", "-j", "FLCLASH_DIVERT6").Run()
	_ = exec.Command("ip6tables", "-w", "2", "-t", "mangle", "-I", "FLCLASH_PRE6", "1", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN").Run()
	_ = exec.Command("ip6tables", "-w", "2", "-t", "mangle", "-I", "FLCLASH_OUT6", "1", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN").Run()
	return nil
}

func teardownTProxy() error {
	clean := [][]string{
		{"iptables", "-w", "2", "-t", "nat", "-D", "OUTPUT", "-j", "FLCLASH_DNS"},
		{"iptables", "-w", "2", "-t", "nat", "-D", "PREROUTING", "-j", "FLCLASH_DNS"},
		{"iptables", "-w", "2", "-t", "nat", "-F", "FLCLASH_DNS"},
		{"iptables", "-w", "2", "-t", "nat", "-X", "FLCLASH_DNS"},
		{"iptables", "-w", "2", "-t", "filter", "-D", "OUTPUT", "-j", "FLCLASH_DOT"},
		{"iptables", "-w", "2", "-t", "filter", "-F", "FLCLASH_DOT"},
		{"iptables", "-w", "2", "-t", "filter", "-X", "FLCLASH_DOT"},
		{"iptables", "-w", "2", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "--transparent", "-j", "FLCLASH_DIVERT"},
		{"iptables", "-w", "2", "-t", "mangle", "-D", "PREROUTING", "-j", "FLCLASH_PRE"},
		{"iptables", "-w", "2", "-t", "mangle", "-D", "OUTPUT", "-j", "FLCLASH_OUT"},
		{"iptables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_DIVERT"},
		{"iptables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_PRE"},
		{"iptables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_OUT"},
		{"iptables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_DIVERT"},
		{"iptables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_PRE"},
		{"iptables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_OUT"},
		{"ip", "rule", "del", "fwmark", tproxyMarkHexMask, "table", routeTableID},
		{"ip", "route", "flush", "table", routeTableID},
		{"ip6tables", "-w", "2", "-t", "filter", "-D", "OUTPUT", "-j", "FLCLASH_V6_BLOCK"},
		{"ip6tables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-j", "FLCLASH_V6_BLOCK"},
		{"ip6tables", "-w", "2", "-t", "filter", "-F", "FLCLASH_V6_BLOCK"},
		{"ip6tables", "-w", "2", "-t", "filter", "-X", "FLCLASH_V6_BLOCK"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "--transparent", "-j", "FLCLASH_DIVERT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-D", "PREROUTING", "-j", "FLCLASH_PRE6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-D", "OUTPUT", "-j", "FLCLASH_OUT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_DIVERT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_PRE6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-F", "FLCLASH_OUT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_DIVERT6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_PRE6"},
		{"ip6tables", "-w", "2", "-t", "mangle", "-X", "FLCLASH_OUT6"},
		{"ip", "-6", "rule", "del", "fwmark", tproxyMarkHexMask, "table", routeTableID},
		{"ip", "-6", "route", "flush", "table", routeTableID},
	}
	teardownFirewallBypassRules()
	for _, c := range clean {
		_ = exec.Command(c[0], c[1:]...).Run()
	}
	setWlanIPv6Disabled(false)
	return nil
}

func runCmd(name string, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func pickFreeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, nil
}

func waitTCPReady(addr string, done <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return errors.New("core exited during startup")
		default:
		}
		c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for core %s", addr)
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
