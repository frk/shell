package sshell

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type command struct {
	// the full (including args) command being executed
	str string
	// the stdout of the command
	out []byte
	// the stderr of the command
	err []byte
	// the exit status of the command
	exit string
}

func (c command) String() string {
	return fmt.Sprintf("command: %q\n - exit code: %q\n - stdout: %s\n - stderr: %s",
		c.str, c.exit, string(c.out), string(c.err))
}

type cmderror struct {
	c command
}

func (e cmderror) Error() string {
	return fmt.Sprintf("command: %q\n - exit code: %s\n - stderr: %s",
		e.c.str, e.c.exit, string(e.c.err))
}

// Shell represents a remote login shell.
type Shell struct {
	host string
	user string

	client *ssh.Client
	sess   *ssh.Session
	motd   string

	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader

	// the command currently executed, gets reset by each invocation of sh.run()
	cmd command
	sch chan error

	boundary string
	err      error
}

// New starts an SSH client connection to the given host, opens
// a new session for the client, and then sets up a Shell.
func New(host, user string) (*Shell, error) {
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

	sh := &Shell{
		host: host,
		user: user,
		sch:  make(chan error),
	}

	sh.client, err = ssh.Dial("tcp", net.JoinHostPort(sh.host, "22"), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: hostKeyCallback,
	})
	if err != nil {
		return nil, err
	}
	sh.sess, err = sh.client.NewSession()
	if err != nil {
		return nil, err
	}
	sh.stdin, err = sh.sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	sh.stdout, err = sh.sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	sh.stderr, err = sh.sess.StderrPipe()
	if err != nil {
		return nil, err
	}
	sh.boundary, err = makeBoundary()
	if err != nil {
		return nil, err
	}

	if err := sh.sess.Shell(); err != nil {
		return nil, err
	}

	// scan motd
	if err := sh.run("echo"); err != nil {
		sh.err = err
	} else {
		sh.motd = string(sh.cmd.out)
	}
	return sh, nil
}

// just a convenience wrapper around fmt.Fprintf that writes to stdin of the shell
func (sh *Shell) printf(format string, a ...interface{}) (err error) {
	if _, err := fmt.Fprintf(sh.stdin, format+"\r\n", a...); err != nil {
		return err
	}
	return err
}

// scans standard output & error
func (sh *Shell) scan() {
	ch := make(chan error)

	// stderr scanner
	go func() {
		s := bufio.NewScanner(sh.stderr)

		// NOTE(to self): Because s.Scan can block indefinitely if nothing is
		// ever written into stderr it cannot be used inside a "default" case
		// of the below select statement as that would cause the program to
		// get stuck... hence this extra goroutine.
		scan := make(chan struct{})
		go func() {
			for s.Scan() {
				scan <- struct{}{}
			}
		}()

	stderrScan:
		for {
			select {
			case <-scan:
				line := s.Bytes()
				sh.cmd.err = append(sh.cmd.err, bytes.TrimSpace(line)...)
				sh.cmd.err = append(sh.cmd.err, '\n')
			case err := <-ch:
				sh.cmd.err = bytes.Trim(sh.cmd.err, "\r\n")
				if e := s.Err(); e != nil && err == nil {
					err = e
				}

				// tell wait() that we are done
				sh.sch <- err
				break stderrScan
			}
		}
	}()

	// stdout scanner
	s := bufio.NewScanner(sh.stdout)

stdoutScan:
	for s.Scan() {
		line := s.Bytes()
		if i := bytes.LastIndex(line, []byte(sh.boundary)); i > -1 {
			status := bytes.TrimSpace(line[i+len(sh.boundary):])
			sh.cmd.exit = string(status)
			sh.cmd.out = bytes.Trim(sh.cmd.out, "\r\n")
			break stdoutScan
		} else {
			sh.cmd.out = append(sh.cmd.out, bytes.TrimSpace(line)...)
			sh.cmd.out = append(sh.cmd.out, '\n')
		}
	}

	// tell stderrScan: above that we're done
	ch <- s.Err()
}

// waits for scan to finish
func (sh *Shell) wait() error {
	if err := <-sh.sch; err != nil {
		sh.err = err
		return err
	}

	if sh.cmd.exit != "0" {
		sh.err = cmderror{sh.cmd}
		return sh.err
	}
	return nil

}

// run runs cmd
func (sh *Shell) run(cmd string, a ...interface{}) error {
	if len(a) > 0 {
		cmd = fmt.Sprintf(cmd, a...)
	}
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimRight(cmd, ";")

	sh.cmd = command{str: cmd}
	if sh.cmd.str == "" {
		return nil
	}

	go sh.scan()
	if err := sh.printf("%s; echo '%s'$?", sh.cmd.str, sh.boundary); err != nil {
		return err
	}
	return sh.wait()
}

// Err retruns the last encountered error.
func (sh *Shell) Err() (err error) {
	return sh.err
}

// Close closes the shell's session and releases its resources.
func (sh *Shell) Close() (err error) {
	if sh.stdin != nil {
		if e := sh.printf("exit"); e != nil {
			err = e
		}
		if e := sh.stdin.Close(); e != nil {
			err = e
		}
	}
	if sh.sess != nil {
		if e := sh.sess.Close(); e != nil {
			err = e
		}
	}
	return err
}

// Exec runs cmd on the remote shell.
func (sh *Shell) Exec(cmd string, a ...interface{}) error {
	if sh.err != nil {
		return sh.err
	}
	if err := sh.run(cmd, a...); err != nil {
		sh.err = err
		return sh.err
	}
	return nil
}

// Out runs cmd on the remote shell and returns its standard output.
func (sh *Shell) Out(cmd string, a ...interface{}) (string, error) {
	if sh.err != nil {
		return "", sh.err
	}
	if err := sh.run(cmd, a...); err != nil {
		sh.err = err
		return "", sh.err
	}

	return string(sh.cmd.out), nil
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