// Copyright 2020 Mohammed El Bahja. All rights reserved.
// Use of this source code is governed by a MIT license.

package darkssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
	"os"
)

func UseAgent() Auth {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		panic(fmt.Errorf("could not find ssh agent: %w", err))
	}
	return Auth{
		ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers),
	}
}
