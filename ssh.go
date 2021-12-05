package shell

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

// sshShell holds the SSH shell session, client, and connection information
type sshShell struct {
	host   string
	user   string
	motd   string
	client *ssh.Client
	*ssh.Session
}

func newSSHShell(host, user string) (sh *sshShell, err error) {
	authMethod, err := sshAgentAuth()
	if err != nil && err != errEmptySSHAgent {
		return nil, err
	} else if err == errEmptySSHAgent {
		authMethod, err = privateKey()
		if err != nil {
			return nil, err
		}
	}
	hostKeyCallback, err := fixedHostKeyFor(host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, "22")
	conf := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
	}

	sh = new(sshShell)
	sh.host = host
	sh.user = user
	if sh.client, err = ssh.Dial("tcp", addr, conf); err != nil {
		return nil, err
	}
	if sh.Session, err = sh.client.NewSession(); err != nil {
		return nil, err
	}
	return sh, nil
}

var errEmptySSHAgent = errors.New("empty_ssh_agent")

func sshAgentAuth() (ssh.AuthMethod, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	client := agent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve signers: %v", err)
	} else if len(signers) == 0 {
		return nil, errEmptySSHAgent
	}

	return ssh.PublicKeysCallback(client.Signers), nil
}

func privateKey() (ssh.AuthMethod, error) {
	keyFile, err := os.Open(os.Getenv("HOME") + "/.ssh/id_rsa")
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	key, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		var e *ssh.PassphraseMissingError
		if !errors.As(err, &e) {
			return nil, err
		}
		pass := passphrasePrompt("Private Key Passphrase: ")
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, pass)
		if err != nil {
			return nil, err
		}
	}

	return ssh.PublicKeys(signer), nil
}

func passphrasePrompt(prompt string) []byte {
	state, err := terminal.GetState(syscall.Stdin)
	if err != nil {
		panic(err)
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		<-c
		_ = terminal.Restore(syscall.Stdin, state)
		os.Exit(1)
	}()

	fmt.Print(prompt)
	pass, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println("")
	if err != nil {
		panic(err)
	}

	signal.Stop(c)
	return pass
}

func fixedHostKeyFor(host string) (ssh.HostKeyCallback, error) {
	knownHostsFile, err := os.Open(os.Getenv("HOME") + "/.ssh/known_hosts")
	if err != nil {
		return nil, err
	}
	defer knownHostsFile.Close()

	knownHosts, err := ioutil.ReadAll(knownHostsFile)
	if err != nil {
		return nil, err
	}

	key := ssh.PublicKey(nil)
	for {
		_, hosts, pubKey, _, rest, err := ssh.ParseKnownHosts(knownHosts)
		if err != nil {
			if err == io.EOF {
				// TODO prompt for confirmation that
				// it's ok to connect to the given host.
				return ssh.InsecureIgnoreHostKey(), nil
			}
			return nil, err
		}
		knownHosts = rest

		for i := range hosts {
			if host == hosts[i] {
				key = pubKey
				break
			}
		}
		if key != nil {
			break
		}
	}

	return ssh.FixedHostKey(key), nil
}

func makeBoundary() (string, error) {
	b := make([]byte, 32/4*3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b64 := base64.URLEncoding.EncodeToString(b)
	return "-----" + b64 + "-----", nil
}
