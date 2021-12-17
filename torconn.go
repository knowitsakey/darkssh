package darkssh

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/armon/go-socks5"
	"github.com/cretz/bine/tor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	err           error
	Auth1         Auth
	MyClient      *Client
	MyAddr        string
	MyUser        string
	MyPort        int
	MyKey         string
	Cmd           string
	MyPass        bool
	Passphrase    bool
	MyAgent       bool
	LocalForward  string
	RemoteForward string
	TorInstancePP int
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
	flag.StringVar(&MyKey, "i", strings.Join([]string{os.Getenv("HOME"), ".ssh", "id_rsa"}, "/"), "private key path.")
	//-J
	//-K
	//-k
	//-L
	flag.StringVar(&LocalForward, "L", "", "Forward a remote service to a local address")
	//-l
	//-M
	//-m
	//-N
	//-n
	//-O
	//-o
	flag.IntVar(&MyPort, "p", 22, "ssh port number.")
	//-Q
	//-q
	flag.StringVar(&RemoteForward, "R", "", "Forward a local service to a remote address")
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
	flag.BoolVar(&MyPass, "goph-pass", false, "ask for ssh password instead of private key.")
	flag.BoolVar(&MyAgent, "goph-MyAgent", true, "use ssh MyAgent for authentication (unix systems only).")
	flag.BoolVar(&Passphrase, "goph-Passphrase", false, "ask for private key Passphrase.")
	flag.IntVar(&TorInstancePP, "t", 22, "tor port number")
}

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
func DialTor(network, MyAddr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	switch network {
	case "tor":
		conn, err := FixedDialTorStreaming(network, MyAddr)
		if err != nil {
			return nil, err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, MyAddr, config)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	default:
		return DialTor("tor", MyAddr, config)
	}
}

func DialTorStreaming(network, MyAddr string) (net.Conn, error) {
	log.Println("\tBuilding connection")
	t, err := tor.Start(nil, nil)
	if err != nil {
		return nil, err
	}
	d, err := t.Dialer(nil, &tor.DialConf{ProxyAddress: SOCKSHostAddress()})
	if err != nil {
		return nil, err
	}
	return d.DialContext(nil, "tcp", MyAddr)
}

func FixedDialTorStreaming(network, MyAddr string) (net.Conn, error) {
	log.Println("\tBuilding connection")
	t, err := tor.Start(nil, nil)
	if err != nil {
		return nil, err
	}
	proxyaddress := SOCKSHostAddress()
	torsocks5addr := tor.DialConf{ProxyAddress: proxyaddress}.ProxyAddress
	dialer, err := proxy.SOCKS5("tcp4", torsocks5addr, nil, proxy.Direct)

	if err != nil {
		return nil, errors.New("Could not connect to TOR_GATE_: " + err.Error())
	}

	return dialer.Dial("tcp4", MyAddr)

	if err != nil {
		return nil, errors.New("Failed to connect: " + err.Error())
	}
	d, err := t.Dialer(nil, &tor.DialConf{ProxyAddress: SOCKSHostAddress()})
	if err != nil {
		return nil, err
	}
	return d.DialContext(nil, "tcp", MyAddr)
}

func command(args []string) string {
	c := ""
	for _, arg := range args {
		c += arg + " "
	}
	return strings.TrimRight(c, " ")
}

func launchSocks(client *Client, port int) error {
	socks5Address := "127.0.0.1:" + strconv.Itoa(port)
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.Dial(network, addr)
		},
	}

	Socks5s, err := socks5.New(conf)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = Socks5s.ListenAndServe("tcp", socks5Address)
	return err
}
func GetFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "127.0.0.1:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}

	return
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
		Cmd = strings.Join(args[1:], " ")
	}

	MyUser = strings.SplitN(args[0], "@", 2)[0]
	MyAddr = strings.SplitN(args[0], "@", 2)[1]

	if MyAgent {
		Auth1 = UseAgent()
	} else if MyPass {
		Auth1 = Password(askPass("Enter SSH Password: "))
	} else {
		Auth1 = Key(MyKey, getPassphrase(Passphrase))
	}

	MyClient, err = NewConn(MyUser, MyAddr, Auth1, func(host string, remote net.Addr, MyKey ssh.PublicKey) error {
		log.Println("connection generated")
		//
		// If you want to connect to new hosts.
		// here your should check new connections public keys
		// if the key not trusted you shuld return an error
		//

		// hostFound: is host in known hosts file.
		// err: error if key not in known hosts file OR host in known hosts file but key changed!
		hostFound, err := CheckKnownHost(host, remote, MyKey, "")
		log.Println("host:", host, "remote:", remote, "key", MyKey)
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
		if askIsHostTrusted(host, MyKey) == false {

			// Make sure to return error on non trusted keys.
			return errors.New("you typed no, aborted!")
		}

		// Add the new host to known hosts file.
		return AddKnownHost(host, remote, MyKey, "")
	})

	if err != nil {
		panic(err)
	}

	// Close client net connection
	defer MyClient.Close()

	if LocalForward != "" {
		MyClient.Mode = '>'
		var wg sync.WaitGroup
		//    logger.Printf("%s starting", path.Base(os.Args[0]))
		wg.Add(1)
		go MyClient.BindTunnel(ctx, &wg)
		wg.Wait()
	}
	if RemoteForward != "" {
		MyClient.Mode = '<'
		var wg sync.WaitGroup
		//    logger.Printf("%s starting", path.Base(os.Args[0]))
		wg.Add(1)
		go MyClient.BindTunnel(ctx, &wg)
		wg.Wait()
	}
	// If the Cmd flag exists

	if Cmd != "" {

		out, err := MyClient.Run(Cmd)

		fmt.Println(string(out), err)
		return
	}
	port, err := GetFreePort()
	launchSocks(MyClient, port)
	// else open interactive mode.
	if err = MyClient.Interact(); err != nil {
		log.Fatal(err)
	}
}

func askPass(msg string) string {

	fmt.Print(msg)

	MyPass, err := terminal.ReadPassword(0)

	if err != nil {
		panic(err)
	}

	fmt.Println("")

	return strings.TrimSpace(string(MyPass))
}

func getPassphrase(ask bool) string {

	/*if ask {

		return askPass("Enter Private Key Passphrase: ")
	}
	*/
	return ""
}

func askIsHostTrusted(host string, MyKey ssh.PublicKey) bool {

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Unknown Host: %s \nFingerprint: %s \n", host, ssh.FingerprintSHA256(MyKey))
	fmt.Print("Would you like to add it? type yes or no: ")

	a, err := reader.ReadString('\n')

	if err != nil {
		log.Fatal(err)
	}

	return strings.ToLower(strings.TrimSpace(a)) == "yes"
}
