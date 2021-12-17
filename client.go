// Copyright 2020 Mohammed El Bahja. All rights reserved.
// Use of this source code is governed by a MIT license.

package darkssh

import (
	//"github.com/eyedeekay/sshtunnel/tunnel"
	"golang.org/x/crypto/ssh"
	"strconv"
	"time"
)

type Interactive struct {
	Port  int
	Conn  *ssh.Client
	Proto string
}

type Client struct {
	*Tunnel
	*Interactive
	Auth
}

// Connect to ssh and get client, the host public key must be in known hosts.
func New(user string, addr string, auth Auth) (c *Client, err error) {
	callback, err := DefaultKnownHosts()
	if err != nil {
		return
	}

	c, err = NewConn(user, addr, auth, callback)
	return
}

// Connect to ssh and get client without cheking knownhosts.
// PLEASE AVOID USING THIS, UNLESS YOU KNOW WHAT ARE YOU DOING!
// if there a "man in the middle proxy", this can harm you!
// You can add the key to know hosts and use New() func instead!
func NewUnknown(user string, addr string, auth Auth) (*Client, error) {

	return NewConn(user, addr, auth, ssh.InsecureIgnoreHostKey())
}

// Get new client connection.
func NewConn(user string, addr string, auth Auth, callback ssh.HostKeyCallback) (c *Client, err error) {

	c = &Client{
		Interactive: &Interactive{
			Port: 22,
		},

		Tunnel: &Tunnel{
			HostAddr: addr,
			User:     user,
			HostKeys: callback,
		},
	}

	err = Conn(c, &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		Timeout:         600 * time.Second,
		HostKeyCallback: callback,
	})

	return
}

func NewConn2(user string, addr string, auth Auth, hsaddr string, port int, doubleport int, callback ssh.HostKeyCallback) (c *ssh.Client, err error) {
	//var err error
	//socks5Address := "127.0.0.1:" + strconv.Itoa(doubleport)
	//err = Conn(c, &ssh.ClientConfig{
	//	User:            c.User,
	//	Auth:            auth,
	//	Timeout:         600 * time.Second,
	//	HostKeyCallback: callback,
	//})
	sshConf := &ssh.ClientConfig{
		User:            "based",
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         600 * time.Second,
	}
	proxyAddress := "127.0.0.1:" + strconv.Itoa(port)
	tp, err := NewTorGate(proxyAddress)

	if err != nil {
		return nil, err
	}
	conn1, err := tp.DialTor(hsaddr + ":22")
	//d, err := torCtx.Dialer(ctx, conf1)
	//conn1, err := d.DialContext(ctx, "tcp", hsaddr)
	if err != nil {
		return nil, err
	}

	conn2, chans, reqs, err := ssh.NewClientConn(conn1, proxyAddress, sshConf)
	if err != nil {
		return nil, err
	}

	//torProxy1.client, err := &ssh.NewClient(c, chans, reqs)
	//client1 := &ssh.NewClient(c, chans, reqs
	c = ssh.NewClient(conn2, chans, reqs)
	return c, err

}

// Get new ssh session from client connection
// See: https://pkg.go.dev/golang.org/x/crypto/ssh?tab=doc#Session
func (c Client) NewSession() (*ssh.Session, error) {

	return c.Conn.NewSession()
}

// Run a command over ssh connection
func (c Client) Run(cmd string) ([]byte, error) {

	var (
		err  error
		sess *ssh.Session
	)

	if sess, err = c.NewSession(); err != nil {
		return nil, err
	}

	defer sess.Close()

	return sess.CombinedOutput(cmd)
}

// Close client net connection.
func (c Client) Close() error {

	return c.Conn.Conn.Close()
}

// Upload a local file to remote machine!
func (c Client) Upload(localPath string, remotePath string) error {

	return Upload(c.Conn, localPath, remotePath)
}

// Download file from remote machine!
func (c Client) Download(remotePath string, localPath string) error {

	return Download(c.Conn, remotePath, localPath)
}
