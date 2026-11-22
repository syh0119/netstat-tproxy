//go:build !android

package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const daemonAuthTimeout = 5 * time.Second

type daemonAuthParams struct {
	Token string `json:"token"`
}

// StartDaemonServer runs a persistent loopback IPC listener for Android root mode.
// Frontend disconnects only close the UI session and never terminate mihomo.
func StartDaemonServer(listenAddr, expectedToken string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	var sessionMu sync.Mutex
	var activeCancel func()

	for {
		accepted, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}

		go func(c net.Conn) {
			if tcpConn, ok := c.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
			}
			if !authenticateDaemonPeer(c, expectedToken) {
				_ = c.Close()
				return
			}

			sessionMu.Lock()
			if activeCancel != nil {
				activeCancel()
			}
			var closeOnce sync.Once
			cancelFn := func() {
				closeOnce.Do(func() { _ = c.Close() })
			}
			activeCancel = cancelFn
			sessionMu.Unlock()

			serveDaemonSession(c, cancelFn)
		}(accepted)
	}
}

func authenticateDaemonPeer(c net.Conn, expectedToken string) bool {
	if expectedToken == "" {
		return false
	}
	_ = c.SetReadDeadline(time.Now().Add(daemonAuthTimeout))
	data, err := readFrame(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return false
	}

	var call MethodCall
	if err := json.Unmarshal(data, &call); err != nil || call.Method != "auth" {
		return false
	}
	var params daemonAuthParams
	if err := json.Unmarshal(call.Arguments, &params); err != nil {
		return false
	}

	expectedSum := sha256.Sum256([]byte(expectedToken))
	actualSum := sha256.Sum256([]byte(params.Token))
	if subtle.ConstantTimeCompare(expectedSum[:], actualSum[:]) != 1 {
		resp := encodeResponse(MethodResponse{
			ID: call.ID,
			Error: &MethodError{
				Code:    "unauthorized",
				Message: "invalid daemon token",
			},
		})
		writeMu.Lock()
		_ = c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
		_, _ = writeFrame(c, resp)
		writeMu.Unlock()
		return false
	}

	resp := encodeResponse(MethodResponse{ID: call.ID, Result: true})
	writeMu.Lock()
	_ = c.SetWriteDeadline(time.Now().Add(ipcWriteTimeout))
	_, writeErr := writeFrame(c, resp)
	_ = c.SetWriteDeadline(time.Time{})
	writeMu.Unlock()
	return writeErr == nil
}

func serveDaemonSession(c ipcConn, closeFn func()) {
	defer func() {
		connMu.Lock()
		if conn == c {
			conn = nil
		}
		connMu.Unlock()
		closeFn()
		handleStopLog()
	}()

	connMu.Lock()
	conn = c
	deliveryFailureReported.Store(false)
	connMu.Unlock()

	for {
		data, err := readFrame(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logError("daemon read error: %v", err)
			}
			return
		}

		call := &MethodCall{}
		if err := json.Unmarshal(data, call); err != nil {
			logError("daemon unmarshal error: %v", err)
			continue
		}
		dispatchMethodCall(call, send)
	}
}
