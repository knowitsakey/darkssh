// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package darkssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type logger interface {
	Printf(string, ...interface{})
}

type Tunnel struct {
	Auth     []ssh.AuthMethod
	HostKeys ssh.HostKeyCallback
	Mode     byte // '>' for forward, '<' for reverse
	User     string
	HostAddr string
	BindAddr string
	DialAddr string

	RetryInterval time.Duration
	keepAlive     KeepAliveConfig

	log logger
}

func (t Tunnel) String() string {
	var left, right string
	Mode := "<?>"
	switch t.Mode {
	case '>':
		left, Mode, right = t.BindAddr, "->", t.DialAddr
	case '<':
		left, Mode, right = t.DialAddr, "<-", t.BindAddr
	}
	return fmt.Sprintf("%s@%s | %s %s %s", t.User, t.HostAddr, left, Mode, right)
}

func (t Tunnel) BindTunnel(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		var once sync.Once // Only print errors once per session
		func() {
			// Connect to the server host via SSH.
			cl, err := ssh.Dial("tcp", t.HostAddr, &ssh.ClientConfig{
				User:            t.User,
				Auth:            t.Auth,
				HostKeyCallback: t.HostKeys,
				Timeout:         5 * time.Second,
			})
			if err != nil {
				once.Do(func() { t.log.Printf("(%v) SSH dial error: %v", t, err) })
				return
			}
			wg.Add(1)
			go t.KeepAliveMonitor(&once, wg, cl)
			defer cl.Close()

			// Attempt to bind to the inbound socket.
			var ln net.Listener
			switch t.Mode {
			case '>':
				ln, err = net.Listen("tcp", t.BindAddr)
			case '<':
				ln, err = cl.Listen("tcp", t.BindAddr)
			}
			if err != nil {
				once.Do(func() { t.log.Printf("(%v) bind error: %v", t, err) })
				return
			}

			// The socket is binded. Make sure we close it eventually.
			bindCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			go func() {
				cl.Wait()
				cancel()
			}()
			go func() {
				<-bindCtx.Done()
				once.Do(func() {}) // Suppress future errors
				ln.Close()
			}()

			t.log.Printf("(%v) binded tunnel", t)
			defer t.log.Printf("(%v) collapsed tunnel", t)

			// Accept all incoming connections.
			for {
				cn1, err := ln.Accept()
				if err != nil {
					once.Do(func() { t.log.Printf("(%v) accept error: %v", t, err) })
					return
				}
				wg.Add(1)
				go t.DialTunnel(bindCtx, wg, cl, cn1)
			}
		}()

		select {
		case <-ctx.Done():
			return
		case <-time.After(t.RetryInterval):
			t.log.Printf("(%v) retrying...", t)
		}
	}
}

func (t Tunnel) DialTunnel(ctx context.Context, wg *sync.WaitGroup, client *ssh.Client, cn1 net.Conn) {
	defer wg.Done()

	// The inbound connection is established. Make sure we close it eventually.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-connCtx.Done()
		cn1.Close()
	}()

	// Establish the outbound connection.
	var cn2 net.Conn
	var err error
	switch t.Mode {
	case '>':
		cn2, err = client.Dial("tcp", t.DialAddr)
	case '<':
		cn2, err = net.Dial("tcp", t.DialAddr)
	}
	if err != nil {
		t.log.Printf("(%v) dial error: %v", t, err)
		return
	}

	go func() {
		<-connCtx.Done()
		cn2.Close()
	}()

	t.log.Printf("(%v) connection established", t)
	defer t.log.Printf("(%v) connection closed", t)

	// Copy bytes from one connection to the other until one side closes.
	var once sync.Once
	var wg2 sync.WaitGroup
	wg2.Add(2)
	go func() {
		defer wg2.Done()
		defer cancel()
		if _, err := io.Copy(cn1, cn2); err != nil {
			once.Do(func() { t.log.Printf("(%v) connection error: %v", t, err) })
		}
		once.Do(func() {}) // Suppress future errors
	}()
	go func() {
		defer wg2.Done()
		defer cancel()
		if _, err := io.Copy(cn2, cn1); err != nil {
			once.Do(func() { t.log.Printf("(%v) connection error: %v", t, err) })
		}
		once.Do(func() {}) // Suppress future errors
	}()
	wg2.Wait()
}

// KeepAliveMonitor periodically sends messages to invoke a response.
// If the server does not respond after some period of time,
// assume that the underlying net.Conn abruptly died.
func (t Tunnel) KeepAliveMonitor(once *sync.Once, wg *sync.WaitGroup, client *ssh.Client) {
	defer wg.Done()
	if t.keepAlive.Interval == 0 || t.keepAlive.CountMax == 0 {
		return
	}

	// Detect when the SSH connection is closed.
	wait := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		wait <- client.Wait()
	}()

	// Repeatedly check if the remote server is still alive.
	var aliveCount int32
	ticker := time.NewTicker(time.Duration(t.keepAlive.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-wait:
			if err != nil && err != io.EOF {
				once.Do(func() { t.log.Printf("(%v) SSH error: %v", t, err) })
			}
			return
		case <-ticker.C:
			if n := atomic.AddInt32(&aliveCount, 1); n > int32(t.keepAlive.CountMax) {
				once.Do(func() { t.log.Printf("(%v) SSH keep-alive termination", t) })
				client.Close()
				return
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				atomic.StoreInt32(&aliveCount, 0)
			}
		}()
	}
}
