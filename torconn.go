package darkssh

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cretz/bine/tor"
	"golang.org/x/crypto/ssh"
)

// TORHost is the host where Tor is running
var TORHost = "127.0.0.1"

// SOCKSPort is the port used for the Tor SOCKS proxy
var SOCKSPort = "9050"

// CONTROLPort is the port used for controlling Tor
var CONTROLPort = "9051"

// SOCKSHostAddress gives you the address of the Tor SOCKS port
func SOCKSHostAddress() string {
	return TORHost + ":" + SOCKSPort
}

// CONTROLHostAddress gets you the address of the Tor Control Port
func CONTROLHostAddress() string {
	return TORHost + ":" + SOCKSPort
}

const (
	// TORTCP a TOR TCP session
	TORTCP string = "tor"
)

// DialTor returns an ssh.Client configured to connect via Tor. It accepts
// "st" or "dg" in the "Network" parameter, for "streaming" or "datagram"
// based connections. It is otherwise identical to ssh.Dial
func DialTor(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	switch network {
	case "tor":
		conn, err := DialTorStreaming(network, addr)
		if err != nil {
			return nil, err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	default:
		return DialTor("tor", addr, config)
	}
}

func DialTorStreaming(network, addr string) (net.Conn, error) {
	log.Println("\tBuilding connection")
	t, err := tor.Start(nil, nil)
	if err != nil {
		return nil, err
	}
	d, err := t.Dialer(nil, &tor.DialConf{ProxyAddress: SOCKSHostAddress()})
	if err != nil {
		return nil, err
	}
	return d.DialContext(nil, "tcp", addr)
}

var (
	err           error
	auth          Auth
	client        *Client
	addr          string
	user1         string
	port          int
	key           string
	cmd           string
	pass          bool
	passphrase    bool
	agent1        bool
	localforward  string
	remoteforward string
)

func init() {
	//-4 ipv4 only
	//-6 ipv6 only
	//-tor enforce Tor use
	//-i2p i2p use
	//-i2pdg i2p datagram use
	//-A enable auth agent1 forwarding
	//-a disable auth agent1 forwarding
	//-B bind to the address of a specific interface, ignored on tor and i2p connections whre it is automatically overridden
	//-b bind address for local machine, ignored on tor and i2p connections where it is automatically overridden
	//-C
	//-c
	//-D
	//-E
	//-e
	//-F
	//-f
	//-G
	//-g
	//-I
	flag.StringVar(&key, "i", strings.Join([]string{os.Getenv("HOME"), ".ssh", "id_rsa"}, "/"), "private key path.")
	//-J
	//-K
	//-k
	//-L
	flag.StringVar(&localforward, "L", "", "Forward a remote service to a local address")
	//-l
	//-M
	//-m
	//-N
	//-n
	//-O
	//-o
	flag.IntVar(&port, "p", 22, "ssh port number.")
	//-Q
	//-q
	flag.StringVar(&remoteforward, "R", "", "Forward a local service to a remote address")
	//-R
	//-S
	//-s
	//-T
	//-t
	//-V
	//-v
	//-W
	//-w
	//-X
	//-x
	//-Y
	//-y
	flag.BoolVar(&pass, "goph-pass", false, "ask for ssh password instead of private key.")
	flag.BoolVar(&agent1, "goph-agent1", true, "use ssh agent1 for authentication (unix systems only).")
	flag.BoolVar(&passphrase, "goph-passphrase", false, "ask for private key passphrase.")
}

func command(args []string) string {
	c := ""
	for _, arg := range args {
		c += arg + " "
	}
	return strings.TrimRight(c, " ")
}

func Connect() {

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		log.Printf("received %v - initiating shutdown", <-sigc)
		cancel()
	}()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("What SSH server do you want to connect to? user@addr")
	}

	if len(args) >= 2 {
		cmd = strings.Join(args[1:], " ")
	}

	user1 = strings.SplitN(args[0], "@", 2)[0]
	addr = strings.SplitN(args[0], "@", 2)[1]

	if agent1 {
		auth = UseAgent()
	} else if pass {
		auth = Password(askPass("Enter SSH Password: "))
	} else {
		auth = Key(key, getPassphrase(passphrase))
	}

	client, err = NewConn(user1, addr, auth, func(host string, remote net.Addr, key ssh.PublicKey) error {
		log.Println("connection generated")
		//
		// If you want to connect to new hosts.
		// here your should check new connections public keys
		// if the key not trusted you shuld return an error
		//

		// hostFound: is host in known hosts file.
		// err: error if key not in known hosts file OR host in known hosts file but key changed!
		hostFound, err := CheckKnownHost(host, remote, key, "")
		log.Println("host:", host, "remote:", remote, "key", key)
		// Host in known hosts but key mismatch!
		// Maybe because of MAN IN THE MIDDLE ATTACK!
		if hostFound && err != nil {
			return err
		}

		// handshake because public key already exists.
		if hostFound && err == nil {
			return nil
		}

		// Ask user to check if he trust the host public key.
		if askIsHostTrusted(host, key) == false {

			// Make sure to return error on non trusted keys.
			return errors.New("you typed no, aborted!")
		}

		// Add the new host to known hosts file.
		return AddKnownHost(host, remote, key, "")
	})

	if err != nil {
		panic(err)
	}

	// Close client net connection
	defer client.Close()

	if localforward != "" {
		client.Mode = '>'
		var wg sync.WaitGroup
		//    logger.Printf("%s starting", path.Base(os.Args[0]))
		wg.Add(1)
		go client.BindTunnel(ctx, &wg)
		wg.Wait()
	}
	if remoteforward != "" {
		client.Mode = '<'
		var wg sync.WaitGroup
		//    logger.Printf("%s starting", path.Base(os.Args[0]))
		wg.Add(1)
		go client.BindTunnel(ctx, &wg)
		wg.Wait()
	}
	// If the cmd flag exists
	if cmd != "" {

		out, err := client.Run(cmd)

		fmt.Println(string(out), err)
		return
	}

	// else open interactive mode.
	if err = client.Interact(); err != nil {
		log.Fatal(err)
	}
}

func askPass(msg string) string {

	fmt.Print(msg)

	pass, err := terminal.ReadPassword(0)

	if err != nil {
		panic(err)
	}

	fmt.Println("")

	return strings.TrimSpace(string(pass))
}

func getPassphrase(ask bool) string {

	if ask {

		return askPass("Enter Private Key Passphrase: ")
	}

	return ""
}

func askIsHostTrusted(host string, key ssh.PublicKey) bool {

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Unknown Host: %s \nFingerprint: %s \n", host, ssh.FingerprintSHA256(key))
	fmt.Print("Would you like to add it? type yes or no: ")

	a, err := reader.ReadString('\n')

	if err != nil {
		log.Fatal(err)
	}

	return strings.ToLower(strings.TrimSpace(a)) == "yes"
}
