package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type RegionPreset struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Alpha    string `json:"alpha"`
	Numeric  string `json:"numeric"`
	Locale   string `json:"locale"`
	Timezone string `json:"timezone"`
}

var regionPresets = []RegionPreset{
	{Code: "US", Name: "美国", Alpha: "T-Mobile", Numeric: "310260", Locale: "en-US", Timezone: "America/New_York"},
	{Code: "JP", Name: "日本", Alpha: "NTT DOCOMO", Numeric: "44010", Locale: "ja-JP", Timezone: "Asia/Tokyo"},
	{Code: "GB", Name: "英国", Alpha: "O2", Numeric: "23410", Locale: "en-GB", Timezone: "Europe/London"},
	{Code: "KR", Name: "韩国", Alpha: "SK Telecom", Numeric: "45005", Locale: "ko-KR", Timezone: "Asia/Seoul"},
	{Code: "TW", Name: "台湾", Alpha: "Chunghwa Telecom", Numeric: "46692", Locale: "zh-TW", Timezone: "Asia/Taipei"},
	{Code: "HK", Name: "香港", Alpha: "CSL", Numeric: "45400", Locale: "zh-HK", Timezone: "Asia/Hong_Kong"},
	{Code: "SG", Name: "新加坡", Alpha: "Singtel", Numeric: "52501", Locale: "en-SG", Timezone: "Asia/Singapore"},
	{Code: "DE", Name: "德国", Alpha: "T-Mobile", Numeric: "26201", Locale: "de-DE", Timezone: "Europe/Berlin"},
	{Code: "CA", Name: "加拿大", Alpha: "Rogers", Numeric: "302720", Locale: "en-CA", Timezone: "America/Toronto"},
	{Code: "AU", Name: "澳大利亚", Alpha: "Telstra", Numeric: "50501", Locale: "en-AU", Timezone: "Australia/Sydney"},
	{Code: "MY", Name: "马来西亚", Alpha: "Maxis", Numeric: "50212", Locale: "ms-MY", Timezone: "Asia/Kuala_Lumpur"},
	{Code: "TH", Name: "泰国", Alpha: "AIS", Numeric: "52001", Locale: "th-TH", Timezone: "Asia/Bangkok"},
	{Code: "FR", Name: "法国", Alpha: "Orange", Numeric: "20801", Locale: "fr-FR", Timezone: "Europe/Paris"},
	{Code: "IT", Name: "意大利", Alpha: "TIM", Numeric: "22201", Locale: "it-IT", Timezone: "Europe/Rome"},
	{Code: "ES", Name: "西班牙", Alpha: "Movistar", Numeric: "21407", Locale: "es-ES", Timezone: "Europe/Madrid"},
	{Code: "NL", Name: "荷兰", Alpha: "KPN", Numeric: "20408", Locale: "nl-NL", Timezone: "Europe/Amsterdam"},
	{Code: "CH", Name: "瑞士", Alpha: "Swisscom", Numeric: "22801", Locale: "de-CH", Timezone: "Europe/Zurich"},
	{Code: "SE", Name: "瑞典", Alpha: "Telia", Numeric: "24001", Locale: "sv-SE", Timezone: "Europe/Stockholm"},
	{Code: "NO", Name: "挪威", Alpha: "Telenor", Numeric: "24201", Locale: "nb-NO", Timezone: "Europe/Oslo"},
	{Code: "FI", Name: "芬兰", Alpha: "Elisa", Numeric: "24405", Locale: "fi-FI", Timezone: "Europe/Helsinki"},
	{Code: "PL", Name: "波兰", Alpha: "Orange", Numeric: "26003", Locale: "pl-PL", Timezone: "Europe/Warsaw"},
	{Code: "IE", Name: "爱尔兰", Alpha: "Vodafone", Numeric: "27201", Locale: "en-IE", Timezone: "Europe/Dublin"},
	{Code: "RU", Name: "俄罗斯", Alpha: "MTS", Numeric: "25001", Locale: "ru-RU", Timezone: "Europe/Moscow"},
	{Code: "TR", Name: "土耳其", Alpha: "Turkcell", Numeric: "28601", Locale: "tr-TR", Timezone: "Europe/Istanbul"},
	{Code: "AE", Name: "阿联酋", Alpha: "Etisalat", Numeric: "42402", Locale: "ar-AE", Timezone: "Asia/Dubai"},
	{Code: "BR", Name: "巴西", Alpha: "Vivo", Numeric: "72406", Locale: "pt-BR", Timezone: "America/Sao_Paulo"},
	{Code: "MX", Name: "墨西哥", Alpha: "Telcel", Numeric: "334020", Locale: "es-MX", Timezone: "America/Mexico_City"},
	{Code: "AR", Name: "阿根廷", Alpha: "Claro", Numeric: "722310", Locale: "es-AR", Timezone: "America/Argentina/Buenos_Aires"},
	{Code: "NZ", Name: "新西兰", Alpha: "Spark", Numeric: "53005", Locale: "en-NZ", Timezone: "Pacific/Auckland"},
	{Code: "IN", Name: "印度", Alpha: "Airtel", Numeric: "40410", Locale: "en-IN", Timezone: "Asia/Kolkata"},
	{Code: "ID", Name: "印尼", Alpha: "Telkomsel", Numeric: "51010", Locale: "id-ID", Timezone: "Asia/Jakarta"},
	{Code: "PH", Name: "菲律宾", Alpha: "Globe", Numeric: "51502", Locale: "en-PH", Timezone: "Asia/Manila"},
	{Code: "VN", Name: "越南", Alpha: "Viettel", Numeric: "45204", Locale: "vi-VN", Timezone: "Asia/Ho_Chi_Minh"},
}

var multiTimezoneCountries = map[string]bool{
	"US": true, "CA": true, "AU": true, "RU": true, "BR": true, "MX": true, "ID": true,
}

var simOperatorPropKeys = []string{
	"gsm.sim.operator.iso-country",
	"gsm.sim.operator.alpha",
	"gsm.sim.operator.numeric",
	"gsm.operator.iso-country",
	"gsm.operator.alpha",
	"gsm.operator.numeric",
	"gsm.sim.operator.default-name",
	"gsm.sim.operator.orig.alpha",
	"gsm.operator.orig.alpha",
}

var localeAndRegionPropKeys = []string{
	"persist.sys.locale",
	"persist.sys.language",
	"persist.sys.country",
	"ro.product.locale",
	"ro.product.locale.language",
	"ro.product.locale.region",
	"ro.miui.region",
	"ro.miui.build.region",
	"ro.config.region",
}

type regionBaseline struct {
	Props        map[string]string `json:"props"`
	Timezone     string            `json:"timezone"`
	AutoTimeZone bool              `json:"autoTimeZone"`
}

type regionState struct {
	Enabled           bool   `json:"enabled"`
	Code              string `json:"code"`
	AppliedTimezone   string `json:"appliedTimezone,omitempty"`
	DetectedExitIP    string `json:"detectedExitIp,omitempty"`
	SpoofSim          bool   `json:"spoofSim"`
	SpoofLocale       bool   `json:"spoofLocale"`
	SpoofTimezone     bool   `json:"spoofTimezone"`
	AutoMatchProxy    bool   `json:"autoMatchProxy"`
	AutoRestoreOnStop bool   `json:"autoRestoreOnStop"`
}

type regionApplyRequest struct {
	Code           string `json:"code"`
	Timezone       string `json:"timezone,omitempty"`
	SpoofSim       *bool  `json:"spoofSim,omitempty"`
	SpoofLocale    *bool  `json:"spoofLocale,omitempty"`
	SpoofTimezone  *bool  `json:"spoofTimezone,omitempty"`
	AutoMatchProxy *bool  `json:"autoMatchProxy,omitempty"`
}

type regionConfigRequest struct {
	SpoofSim          *bool `json:"spoofSim,omitempty"`
	SpoofLocale       *bool `json:"spoofLocale,omitempty"`
	SpoofTimezone     *bool `json:"spoofTimezone,omitempty"`
	AutoMatchProxy    *bool `json:"autoMatchProxy,omitempty"`
	AutoRestoreOnStop *bool `json:"autoRestoreOnStop,omitempty"`
}

type regionSyncRequest struct {
	Code      string `json:"code"`
	IP        string `json:"ip,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	MixedPort int    `json:"mixedPort,omitempty"`
}

type regionStatusResponse struct {
	Enabled           bool           `json:"enabled"`
	Code              string         `json:"code"`
	SpoofSim          bool           `json:"spoofSim"`
	SpoofLocale       bool           `json:"spoofLocale"`
	SpoofTimezone     bool           `json:"spoofTimezone"`
	AutoMatchProxy    bool           `json:"autoMatchProxy"`
	AutoRestoreOnStop bool           `json:"autoRestoreOnStop"`
	DetectedExitIP    string         `json:"detectedExitIp,omitempty"`
	ActiveIso         string         `json:"activeIso"`
	ActiveAlpha       string         `json:"activeAlpha"`
	ActiveNumeric     string         `json:"activeNumeric"`
	ActiveLocale      string         `json:"activeLocale"`
	ActiveTimezone    string         `json:"activeTimezone"`
	Presets           []RegionPreset `json:"presets"`
}

type RegionManager struct {
	mu           sync.Mutex
	stateDir     string
	stateFile    string
	baselineFile string
	state        regionState
	guardStop    chan struct{}
	probeCancel  context.CancelFunc
}

func newRegionManager(stateDir string) *RegionManager {
	if stateDir == "" {
		stateDir = "/data/adb/flclash-tproxy"
	}
	return &RegionManager{
		stateDir:     stateDir,
		stateFile:    filepath.Join(stateDir, "region_state.json"),
		baselineFile: filepath.Join(stateDir, "region_baseline.json"),
		state: regionState{
			Code:              "US",
			SpoofSim:          true,
			SpoofLocale:       true,
			SpoofTimezone:     true,
			AutoMatchProxy:    true,
			AutoRestoreOnStop: true,
		},
	}
}

func (rm *RegionManager) init() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if data, err := os.ReadFile(rm.stateFile); err == nil {
		var st regionState
		if json.Unmarshal(data, &st) == nil && st.Code != "" {
			rm.state = st
		}
	}
	if rm.state.Enabled {
		if preset, ok := resolvePreset(rm.state.Code, rm.state.AppliedTimezone); ok {
			if err := rm.applyLocked(preset, rm.state); err != nil {
				log.Printf("region auto-apply %s failed: %v", preset.Code, err)
			} else {
				rm.startGuardLocked()
			}
		}
	}
}

func findRegionPreset(code string) (RegionPreset, bool) {
	c := strings.ToUpper(strings.TrimSpace(code))
	for _, p := range regionPresets {
		if p.Code == c {
			return p, true
		}
	}
	return RegionPreset{}, false
}

func resolvePreset(code string, tzOverride string) (RegionPreset, bool) {
	c := strings.ToUpper(strings.TrimSpace(code))
	if len(c) != 2 {
		return RegionPreset{}, false
	}
	p, ok := findRegionPreset(c)
	if !ok {
		if tzOverride == "" {
			return RegionPreset{}, false
		}
		p = RegionPreset{
			Code:     c,
			Name:     c,
			Alpha:    "Carrier",
			Numeric:  "00101",
			Locale:   "en-" + c,
			Timezone: tzOverride,
		}
	} else if tzOverride != "" && strings.Contains(tzOverride, "/") {
		p.Timezone = tzOverride
	}
	return p, true
}

func runResetprop(args ...string) (string, error) {
	candidates := [][]string{
		{"/data/adb/ksu/bin/resetprop"},
		{"/data/adb/ksu/bin/ksud", "resetprop"},
		{"/data/adb/ksud", "resetprop"},
		{"resetprop"},
		{"ksud", "resetprop"},
	}
	for _, base := range candidates {
		bin := base[0]
		if strings.HasPrefix(bin, "/") {
			if _, err := os.Stat(bin); err != nil {
				continue
			}
		} else if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		fullArgs := append(append([]string{}, base[1:]...), args...)
		out, err := exec.Command(bin, fullArgs...).CombinedOutput()
		if err != nil {
			return strings.TrimSpace(string(out)), fmt.Errorf("%s %v failed: %w (%s)", bin, fullArgs, err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	if len(args) == 1 {
		out, err := exec.Command("getprop", args[0]).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	return "", fmt.Errorf("resetprop/ksud binary not found")
}

func getPropVal(key string) string {
	if out, err := runResetprop(key); err == nil {
		return strings.TrimSpace(out)
	}
	out, err := exec.Command("getprop", key).Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func setPropVal(key, val string) error {
	_, err := runResetprop(key, val)
	return err
}

func getAutoTimeZoneEnabled() bool {
	if out, err := exec.Command("cmd", "time_zone_detector", "is_auto_detection_enabled").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		if s == "true" || s == "1" {
			return true
		}
		if s == "false" || s == "0" {
			return false
		}
	}
	if out, err := exec.Command("settings", "get", "global", "auto_time_zone").Output(); err == nil {
		return strings.TrimSpace(string(out)) == "1"
	}
	return true
}

func setDeviceTimezone(tz string, autoEnabled *bool) error {
	if autoEnabled != nil {
		val := "false"
		setNum := "0"
		if *autoEnabled {
			val = "true"
			setNum = "1"
		}
		if err := exec.Command("cmd", "time_zone_detector", "set_auto_detection_enabled", val).Run(); err != nil {
			_ = exec.Command("settings", "put", "global", "auto_time_zone", setNum).Run()
		}
	}
	if tz != "" {
		if err := exec.Command("cmd", "time_zone_detector", "suggest_manual_time_zone", "--zone_id", tz).Run(); err != nil {
			return setPropVal("persist.sys.timezone", tz)
		}
		if cur := getPropVal("persist.sys.timezone"); cur != tz {
			_ = setPropVal("persist.sys.timezone", tz)
		}
	}
	return nil
}

func (rm *RegionManager) disarmLegacyTiktokFixIfActiveLocked() {
	modDir := "/data/adb/modules/tiktok_fix"
	enFile := filepath.Join(modDir, "config", "enabled")
	b, err := os.ReadFile(enFile)
	if err != nil {
		return
	}
	if strings.TrimSpace(string(b)) != "1" {
		return
	}
	_ = os.WriteFile(enFile, []byte("0\n"), 0o644)
	if pidBytes, err := os.ReadFile(filepath.Join(modDir, "config", "guard.pid")); err == nil {
		pid := strings.TrimSpace(string(pidBytes))
		if pid != "" {
			_ = exec.Command("kill", pid).Run()
		}
	}
	restoreScript := filepath.Join(modDir, "bin", "restore.sh")
	if _, err := os.Stat(restoreScript); err == nil {
		_ = exec.Command("/system/bin/sh", restoreScript).Run()
	}
	log.Printf("disarmed legacy tiktok_fix region module before capturing baseline")
}

func (rm *RegionManager) ensureBaselineLocked() error {
	if _, err := os.Stat(rm.baselineFile); err == nil {
		return nil
	}
	rm.disarmLegacyTiktokFixIfActiveLocked()
	_ = os.MkdirAll(rm.stateDir, 0o700)

	props := make(map[string]string)
	for _, k := range simOperatorPropKeys {
		props[k] = getPropVal(k)
	}
	for _, k := range localeAndRegionPropKeys {
		props[k] = getPropVal(k)
	}
	if prodLoc := props["ro.product.locale"]; prodLoc != "" && strings.Contains(prodLoc, "-") {
		parts := strings.SplitN(prodLoc, "-", 2)
		if props["persist.sys.locale"] != prodLoc {
			props["persist.sys.locale"] = prodLoc
			props["persist.sys.language"] = parts[0]
			props["persist.sys.country"] = parts[1]
			props["ro.product.locale.language"] = parts[0]
			props["ro.product.locale.region"] = parts[1]
			props["ro.miui.region"] = parts[1]
			props["ro.miui.build.region"] = parts[1]
			props["ro.config.region"] = parts[1]
		}
	}
	tz := getPropVal("persist.sys.timezone")
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	base := regionBaseline{
		Props:        props,
		Timezone:     tz,
		AutoTimeZone: getAutoTimeZoneEnabled(),
	}
	data, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rm.baselineFile, data, 0o600)
}

func slotFill(key, val string) string {
	cur := getPropVal(key)
	slots := 1
	if cur != "" {
		parts := strings.Split(cur, ",")
		nonEmpty := 0
		for _, p := range parts {
			if strings.TrimSpace(p) != "" {
				nonEmpty++
			}
		}
		if nonEmpty > 1 {
			slots = nonEmpty
		}
	}
	if slots == 1 {
		return val
	}
	out := make([]string, slots)
	for i := range out {
		out[i] = val
	}
	return strings.Join(out, ",")
}

func (rm *RegionManager) applyLocked(preset RegionPreset, st regionState) error {
	if err := rm.ensureBaselineLocked(); err != nil {
		return fmt.Errorf("capture baseline: %w", err)
	}
	var base regionBaseline
	if data, err := os.ReadFile(rm.baselineFile); err == nil {
		_ = json.Unmarshal(data, &base)
	}
	isoLower := strings.ToLower(preset.Code)
	lang := "en"
	country := preset.Code
	if parts := strings.SplitN(preset.Locale, "-", 2); len(parts) == 2 {
		lang = parts[0]
		country = parts[1]
	}

	if st.SpoofSim {
		for _, k := range []string{"gsm.sim.operator.iso-country", "gsm.operator.iso-country"} {
			if err := setPropVal(k, slotFill(k, isoLower)); err != nil {
				return err
			}
		}
		for _, k := range []string{
			"gsm.sim.operator.alpha",
			"gsm.operator.alpha",
			"gsm.sim.operator.default-name",
			"gsm.sim.operator.orig.alpha",
			"gsm.operator.orig.alpha",
		} {
			_ = setPropVal(k, slotFill(k, preset.Alpha))
		}
		for _, k := range []string{"gsm.sim.operator.numeric", "gsm.operator.numeric"} {
			_ = setPropVal(k, slotFill(k, preset.Numeric))
		}
		for _, k := range []string{"ro.miui.region", "ro.miui.build.region", "ro.config.region"} {
			_ = setPropVal(k, preset.Code)
		}
	} else {
		for _, k := range simOperatorPropKeys {
			if v, ok := base.Props[k]; ok {
				_ = setPropVal(k, v)
			}
		}
		for _, k := range []string{"ro.miui.region", "ro.miui.build.region", "ro.config.region"} {
			if v, ok := base.Props[k]; ok {
				_ = setPropVal(k, v)
			}
		}
	}

	if st.SpoofLocale {
		_ = setPropVal("persist.sys.locale", preset.Locale)
		_ = setPropVal("persist.sys.language", lang)
		_ = setPropVal("persist.sys.country", country)
		_ = setPropVal("ro.product.locale", preset.Locale)
		_ = setPropVal("ro.product.locale.language", lang)
		_ = setPropVal("ro.product.locale.region", country)
	} else {
		for _, k := range []string{
			"persist.sys.locale",
			"persist.sys.language",
			"persist.sys.country",
			"ro.product.locale",
			"ro.product.locale.language",
			"ro.product.locale.region",
		} {
			if v, ok := base.Props[k]; ok {
				_ = setPropVal(k, v)
			}
		}
	}

	if st.SpoofTimezone {
		autoOff := false
		if err := setDeviceTimezone(preset.Timezone, &autoOff); err != nil {
			return err
		}
	} else if base.Timezone != "" {
		_ = setDeviceTimezone(base.Timezone, &base.AutoTimeZone)
	}
	return nil
}

func (rm *RegionManager) restoreLocked() error {
	rm.stopGuardLocked()

	data, err := os.ReadFile(rm.baselineFile)
	if err == nil {
		var base regionBaseline
		if json.Unmarshal(data, &base) == nil {
			for k, v := range base.Props {
				_ = setPropVal(k, v)
			}
			_ = setDeviceTimezone(base.Timezone, &base.AutoTimeZone)
		}
	}
	rm.state.Enabled = false
	rm.state.AppliedTimezone = ""
	rm.state.DetectedExitIP = ""
	_ = rm.saveStateLocked()
	return nil
}

func (rm *RegionManager) saveStateLocked() error {
	_ = os.MkdirAll(rm.stateDir, 0o700)
	data, err := json.MarshalIndent(rm.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rm.stateFile, data, 0o600)
}

func (rm *RegionManager) startGuardLocked() {
	if rm.guardStop != nil {
		return
	}
	stopCh := make(chan struct{})
	rm.guardStop = stopCh
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				rm.mu.Lock()
				if !rm.state.Enabled {
					rm.mu.Unlock()
					continue
				}
				preset, ok := resolvePreset(rm.state.Code, rm.state.AppliedTimezone)
				if !ok {
					rm.mu.Unlock()
					continue
				}
				needsReapply := false
				if rm.state.SpoofSim {
					iso := strings.ToLower(getPropVal("gsm.sim.operator.iso-country"))
					if !strings.Contains(iso, strings.ToLower(preset.Code)) {
						needsReapply = true
					}
				}
				if rm.state.SpoofTimezone {
					tz := getPropVal("persist.sys.timezone")
					if tz != preset.Timezone {
						needsReapply = true
					}
				}
				if needsReapply {
					_ = rm.applyLocked(preset, rm.state)
				}
				rm.mu.Unlock()
			}
		}
	}()
}

func (rm *RegionManager) stopGuardLocked() {
	if rm.guardStop != nil {
		close(rm.guardStop)
		rm.guardStop = nil
	}
}

func probeExitLocationViaMixed(ctx context.Context, mixedPort int) (code, tz, ip string) {
	if mixedPort <= 0 {
		mixedPort = 7890
	}
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	if err != nil {
		return "", "", ""
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Endpoint 1: ip-api.com (returns countryCode + exact city timezone + query)
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/?fields=status,countryCode,timezone,query", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			var parsed struct {
				Status      string `json:"status"`
				CountryCode string `json:"countryCode"`
				Timezone    string `json:"timezone"`
				Query       string `json:"query"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&parsed)
			_ = resp.Body.Close()
			if parsed.Status == "success" && parsed.CountryCode != "" {
				return strings.ToUpper(strings.TrimSpace(parsed.CountryCode)), strings.TrimSpace(parsed.Timezone), strings.TrimSpace(parsed.Query)
			}
		}
	}

	// Endpoint 2: ipwho.is fallback
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			var parsed struct {
				Success     bool   `json:"success"`
				CountryCode string `json:"country_code"`
				IP          string `json:"ip"`
				Timezone    struct {
					ID string `json:"id"`
				} `json:"timezone"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&parsed)
			_ = resp.Body.Close()
			if parsed.Success && parsed.CountryCode != "" {
				return strings.ToUpper(strings.TrimSpace(parsed.CountryCode)), strings.TrimSpace(parsed.Timezone.ID), strings.TrimSpace(parsed.IP)
			}
		}
	}
	return "", "", ""
}

func (rm *RegionManager) onTProxyStarted(mixedPort int) {
	rm.mu.Lock()
	if rm.probeCancel != nil {
		rm.probeCancel()
		rm.probeCancel = nil
	}
	if !rm.state.AutoMatchProxy {
		rm.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	rm.probeCancel = cancel
	rm.mu.Unlock()

	go func() {
		defer cancel()
		backoff := []time.Duration{1500 * time.Millisecond, 2500 * time.Millisecond, 4 * time.Second}
		for _, wait := range backoff {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			cc, tz, ip := probeExitLocationViaMixed(ctx, mixedPort)
			if cc == "" {
				continue
			}
			if strings.EqualFold(cc, "CN") {
				log.Printf("auto-region: proxy exit detected as CN (%s), skipping spoof", ip)
				return
			}
			rm.mu.Lock()
			if ctx.Err() != nil || !rm.state.AutoMatchProxy {
				rm.mu.Unlock()
				return
			}
			preset, ok := resolvePreset(cc, tz)
			if ok {
				needApply := !rm.state.Enabled ||
					rm.state.Code != preset.Code ||
					(rm.state.SpoofTimezone && preset.Timezone != "" && getPropVal("persist.sys.timezone") != preset.Timezone)
				if needApply {
					next := rm.state
					next.Enabled = true
					next.Code = preset.Code
					next.AppliedTimezone = preset.Timezone
					next.DetectedExitIP = ip
					if err := rm.applyLocked(preset, next); err != nil {
						log.Printf("auto-region apply %s failed: %v", preset.Code, err)
					} else {
						rm.state = next
						_ = rm.saveStateLocked()
						rm.startGuardLocked()
						log.Printf("auto-region switched to %s (%s) from exit ip %s", preset.Code, preset.Timezone, ip)
					}
				} else if ip != "" && rm.state.DetectedExitIP != ip {
					rm.state.DetectedExitIP = ip
					_ = rm.saveStateLocked()
				}
			}
			rm.mu.Unlock()
			return
		}
	}()
}

func (rm *RegionManager) onTProxyStopped() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.probeCancel != nil {
		rm.probeCancel()
		rm.probeCancel = nil
	}
	if rm.state.AutoMatchProxy && rm.state.AutoRestoreOnStop && rm.state.Enabled {
		if err := rm.restoreLocked(); err != nil {
			log.Printf("auto-region restore on stop failed: %v", err)
		} else {
			log.Printf("auto-region restored native baseline on tproxy stop")
		}
	}
}

func (rm *RegionManager) statusLocked() regionStatusResponse {
	return regionStatusResponse{
		Enabled:           rm.state.Enabled,
		Code:              rm.state.Code,
		SpoofSim:          rm.state.SpoofSim,
		SpoofLocale:       rm.state.SpoofLocale,
		SpoofTimezone:     rm.state.SpoofTimezone,
		AutoMatchProxy:    rm.state.AutoMatchProxy,
		AutoRestoreOnStop: rm.state.AutoRestoreOnStop,
		DetectedExitIP:    rm.state.DetectedExitIP,
		ActiveIso:         getPropVal("gsm.sim.operator.iso-country"),
		ActiveAlpha:       getPropVal("gsm.sim.operator.alpha"),
		ActiveNumeric:     getPropVal("gsm.sim.operator.numeric"),
		ActiveLocale:      getPropVal("persist.sys.locale"),
		ActiveTimezone:    getPropVal("persist.sys.timezone"),
		Presets:           regionPresets,
	}
}

func (s *HelperServer) handleRegionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.region.mu.Lock()
	defer s.region.mu.Unlock()
	writeJSON(w, http.StatusOK, s.region.statusLocked())
}

func (s *HelperServer) handleRegionConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req regionConfigRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": err.Error()})
		return
	}
	s.region.mu.Lock()
	defer s.region.mu.Unlock()

	if req.SpoofSim != nil {
		s.region.state.SpoofSim = *req.SpoofSim
	}
	if req.SpoofLocale != nil {
		s.region.state.SpoofLocale = *req.SpoofLocale
	}
	if req.SpoofTimezone != nil {
		s.region.state.SpoofTimezone = *req.SpoofTimezone
	}
	if req.AutoMatchProxy != nil {
		s.region.state.AutoMatchProxy = *req.AutoMatchProxy
	}
	if req.AutoRestoreOnStop != nil {
		s.region.state.AutoRestoreOnStop = *req.AutoRestoreOnStop
	}
	if s.region.state.Enabled {
		if preset, ok := resolvePreset(s.region.state.Code, s.region.state.AppliedTimezone); ok {
			_ = s.region.applyLocked(preset, s.region.state)
		}
	}
	_ = s.region.saveStateLocked()
	writeJSON(w, http.StatusOK, s.region.statusLocked())
}

func (s *HelperServer) handleRegionApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req regionApplyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": err.Error()})
		return
	}
	preset, ok := resolvePreset(req.Code, req.Timezone)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "unknown_region", "message": "unsupported region code"})
		return
	}

	s.region.mu.Lock()
	defer s.region.mu.Unlock()

	next := s.region.state
	next.Enabled = true
	next.Code = preset.Code
	next.AppliedTimezone = preset.Timezone
	next.DetectedExitIP = ""
	if req.SpoofSim != nil {
		next.SpoofSim = *req.SpoofSim
	}
	if req.SpoofLocale != nil {
		next.SpoofLocale = *req.SpoofLocale
	}
	if req.SpoofTimezone != nil {
		next.SpoofTimezone = *req.SpoofTimezone
	}
	if req.AutoMatchProxy != nil {
		next.AutoMatchProxy = *req.AutoMatchProxy
	}

	if err := s.region.applyLocked(preset, next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "region_apply_failed", "message": err.Error()})
		return
	}
	s.region.state = next
	_ = s.region.saveStateLocked()
	s.region.startGuardLocked()
	writeJSON(w, http.StatusOK, s.region.statusLocked())
}

func (s *HelperServer) handleRegionSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req regionSyncRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": err.Error()})
		return
	}

	s.region.mu.Lock()
	if !s.region.state.AutoMatchProxy {
		resp := s.region.statusLocked()
		s.region.mu.Unlock()
		writeJSON(w, http.StatusOK, resp)
		return
	}
	spoofTZ := s.region.state.SpoofTimezone
	s.region.mu.Unlock()

	cc := strings.ToUpper(strings.TrimSpace(req.Code))
	tz := strings.TrimSpace(req.Timezone)
	ip := strings.TrimSpace(req.IP)

	// If no country code or multi-timezone country without city timezone, probe via mixed proxy.
	if (cc == "" || (spoofTZ && tz == "" && multiTimezoneCountries[cc])) && req.MixedPort != -1 {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		pCC, pTZ, pIP := probeExitLocationViaMixed(ctx, req.MixedPort)
		cancel()
		if cc == "" && pCC != "" {
			cc = pCC
		}
		if tz == "" && pTZ != "" {
			tz = pTZ
		}
		if ip == "" && pIP != "" {
			ip = pIP
		}
	}

	if cc == "" || cc == "CN" {
		s.region.mu.Lock()
		resp := s.region.statusLocked()
		s.region.mu.Unlock()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	preset, ok := resolvePreset(cc, tz)
	if !ok {
		s.region.mu.Lock()
		resp := s.region.statusLocked()
		s.region.mu.Unlock()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	s.region.mu.Lock()
	defer s.region.mu.Unlock()
	if !s.region.state.AutoMatchProxy {
		writeJSON(w, http.StatusOK, s.region.statusLocked())
		return
	}
	needApply := !s.region.state.Enabled ||
		s.region.state.Code != preset.Code ||
		(s.region.state.SpoofTimezone && preset.Timezone != "" && getPropVal("persist.sys.timezone") != preset.Timezone)
	if needApply {
		next := s.region.state
		next.Enabled = true
		next.Code = preset.Code
		next.AppliedTimezone = preset.Timezone
		if ip != "" {
			next.DetectedExitIP = ip
		}
		if err := s.region.applyLocked(preset, next); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "region_sync_failed", "message": err.Error()})
			return
		}
		s.region.state = next
		_ = s.region.saveStateLocked()
		s.region.startGuardLocked()
		log.Printf("auto-region synced to %s (%s) ip=%s", preset.Code, preset.Timezone, ip)
	} else if ip != "" && s.region.state.DetectedExitIP != ip {
		s.region.state.DetectedExitIP = ip
		_ = s.region.saveStateLocked()
	}
	writeJSON(w, http.StatusOK, s.region.statusLocked())
}

func (s *HelperServer) handleRegionRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.region.mu.Lock()
	defer s.region.mu.Unlock()
	if err := s.region.restoreLocked(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "region_restore_failed", "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.region.statusLocked())
}
