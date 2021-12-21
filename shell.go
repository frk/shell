package shell

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// shell implements Shell
type shell struct {
	// for a local shell this will hold the command
	// that starts the interactive shell process
	bin *exec.Cmd
	// for a remote shell this will hold the ssh
	// session and the ssh connection information
	ssh *sshShell

	host   string
	user   string
	motd   string
	client *ssh.Client
	sess   *ssh.Session

	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader

	// the command currently executed, gets reset by each invocation of sh.run()
	cmd      command
	sch      chan error
	retry    map[string]map[string]uint
	boundary string
	coe      bool // continue on error
	err      error
}

// Err retruns the last encountered error.
func (sh *shell) Err() (err error) {
	return sh.err
}

// Close closes the shell's session and releases its resources.
func (sh *shell) Close() (err error) {
	if sh.stdin != nil {
		if e := sh.printf("exit"); e != nil {
			err = e
		}
		if e := sh.stdin.Close(); e != nil {
			err = e
		}
	}
	if sh.bin != nil {
		if e := sh.bin.Wait(); e != nil {
			err = e
		}
	}
	if sh.ssh != nil {
		if e := sh.ssh.Close(); e != nil {
			err = e
		}
	}
	return err
}

// Exec runs cmd in the shell.
func (sh *shell) Exec(cmd string, a ...interface{}) error {
	if sh.err != nil && sh.coe == false {
		return sh.err
	}
	if err := sh.run(cmd, a...); err != nil {
		sh.err = err
		return sh.err
	}
	return nil
}

// Out runs cmd in the shell and returns its standard output.
func (sh *shell) Out(cmd string, a ...interface{}) (string, error) {
	if sh.err != nil && sh.coe == false {
		return "", sh.err
	}
	if err := sh.run(cmd, a...); err != nil {
		sh.err = err
		return "", sh.err
	}

	return string(sh.cmd.out), nil
}

func (sh *shell) retryCount() (count uint) {
	if len(sh.retry) == 0 {
		return 0
	}
	prog := sh.cmd.str
	if ff := strings.Fields(prog); len(ff) > 0 {
		prog = ff[0]
	}

	exit, ok := sh.retry[prog]
	if !ok {
		if exit, ok = sh.retry["*"]; !ok {
			return 0
		}
	}
	count, ok = exit[sh.cmd.exit]
	if !ok {
		if count, ok = exit["*"]; !ok {
			return 0
		}
	}
	return count
}

// just a convenience wrapper around fmt.Fprintf that writes to stdin of the shell
func (sh *shell) printf(format string, a ...interface{}) (err error) {
	if _, err := fmt.Fprintf(sh.stdin, format+"\r\n", a...); err != nil {
		return err
	}
	return err
}

// starts the scanning of standard output & standard error
func (sh *shell) start() {
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
func (sh *shell) wait() error {
	if err := <-sh.sch; err != nil {
		sh.err = scanError{sh.cmd, err}
		return err
	}

	if sh.cmd.exit != "0" {
		sh.err = cmdError{sh.cmd}
		return sh.err
	}
	return nil

}

// run runs cmd
func (sh *shell) run(cmd string, a ...interface{}) error {
	if len(a) > 0 {
		cmd = fmt.Sprintf(cmd, a...)
	}
	cmd = strings.TrimSpace(cmd)
	if strings.HasSuffix(cmd, ";") && !strings.HasSuffix(cmd, "\\;") {
		cmd = cmd[:len(cmd)-1]
	}
	if cmd == "" {
		return nil
	}

	sh.cmd = command{str: cmd}

	go sh.start()
	if err := sh.printf("%s; echo '%s'$?", sh.cmd.str, sh.boundary); err != nil {
		return err
	}
	if err := sh.wait(); err != nil {
		retry := sh.retryCount()
		if retry == 0 {
			return err
		}

		orig := sh.cmd
		for retry > 0 {
			fmt.Printf("retrying %q...\n", orig.str)
			time.Sleep(3 * time.Second)

			sh.cmd = command{str: orig.str}

			go sh.start()
			if e := sh.printf("%s; echo '%s'$?", sh.cmd.str, sh.boundary); e != nil {
				return e
			}
			if e := sh.wait(); e != nil {
				retry -= 1
				continue
			} else {
				err = nil
				break
			}
		}
		sh.cmd = orig
		return err
	}
	return nil
}

// an error caused by a command
type cmdError struct {
	cmd command
}

func (e cmdError) Error() string {
	return fmt.Sprintf("command: %q\n - exit code: %s\n - stderr: %s",
		e.cmd.str, e.cmd.exit, string(e.cmd.err))
}

// an error returned by bufio.Scanner
type scanError struct {
	cmd command
	err error
}

func (e scanError) Error() string {
	return fmt.Sprintf("command: %q\n - bufio.Scanner error: %v",
		e.cmd.str, e.err)
}

// represents a command being executed by shell
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

type Shell interface {
	Err() error
	Close() error
	Exec(cmd string, a ...interface{}) error
	Out(cmd string, a ...interface{}) (string, error)
}

type Config struct {
	// If Host is set, it will be used, together with User, to establish a
	// remote, interactive SSH connection. If User is unset, it will default
	// to $USER environment variable.
	Host, User string
	// If connecting to Host fails, the ConnRetry field can be used to set
	// how many times should the shell try to connect before giving up.
	ConnRetry int
	// If the above Host is unset, then Name will be used as the name, or
	// file path, of the local shell to be executed in interactive mode.
	// If both, Host and Name, are unset, then the $SHELL environment variable
	// will be used to determine which shell to execute, and if that environment
	// variable is not set, then /bin/bash will be executed as default.
	Name string
	// A list of expressions used to configure the shell to re-try commands
	// that returned with a non-zero exit status.
	//
	// An expression MUST be of the following format:
	//
	//	"<prog_name>:<exit_status>:<count>"
	//
	// All three values in the expression MUST be non-empty.
	// - "prog_name" will be used to match the failed command's program name.
	//   Can be set to the wildcard "*" to match any program.
	// - "exit_status" will be used to match the failed command's exit status.
	//   MUST either be an integer in the range 1-255 (inclusive), or it
	//   can be set to the wildcard "*" to match any exit status.
	// - "count" is the number of re-tries that the shell should do.
	//   MUST be an integer greater than 0.
	CmdRetry []string
	// If set to true the shell will keep executing commands even if an error occurs.
	ContinueOnError bool
}

func New(c Config) (_ Shell, err error) {
	sh := new(shell)
	sh.sch = make(chan error)
	sh.retry = make(map[string]map[string]uint)
	sh.coe = c.ContinueOnError
	sh.boundary, err = makeBoundary()
	if err != nil {
		return nil, err
	}

	for _, x := range c.CmdRetry {
		xs := strings.Split(x, ":")
		if len(xs) != 3 {
			return nil, fmt.Errorf("shell: bad retry expression %q", x)
		}

		exits := sh.retry[xs[0]]
		if exits == nil {
			exits = make(map[string]uint)
			sh.retry[xs[0]] = exits
		}

		if s := xs[1]; s != "*" {
			// make sure its a valid non-zero exit status
			u8, err := strconv.ParseUint(s, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("shell: error parsing retry exit status: %v", err)
			}
			if u8 < 1 || 255 < u8 {
				return nil, fmt.Errorf("shell: bad retry exit status: %d", u8)
			}
		}
		count, err := strconv.ParseUint(xs[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("shell: error parsing retry count: %v", err)
		}
		exits[xs[1]] = uint(count)
	}

	if len(c.Host) == 0 {
		if err := initLocal(c.Name, sh); err != nil {
			return nil, err
		}
		return sh, nil
	}

	if err := initSSH(c.Host, c.User, sh); err != nil {
		for retry := c.ConnRetry; retry > 0; retry-- {
			fmt.Printf("retrying ssh to %q...\n", c.Host)
			time.Sleep(3 * time.Second)

			if err := initSSH(c.Host, c.User, sh); err == nil {
				return sh, nil
			}
		}
		return nil, err
	}
	return sh, nil
}

func initLocal(name string, sh *shell) (err error) {
	if name == "" {
		name = os.Getenv("SHELL")
	}
	if name == "" {
		name = "/bin/bash"
	}

	var args []string
	switch name {
	case "/bin/zsh":
		args = []string{"-i", "-s"}
	case "/bin/bash":
		args = []string{"-i"}
	}

	sh.bin = exec.Command(name, args...)
	if sh.stdin, err = sh.bin.StdinPipe(); err != nil {
		return err
	}
	if sh.stdout, err = sh.bin.StdoutPipe(); err != nil {
		return err
	}
	if sh.stderr, err = sh.bin.StderrPipe(); err != nil {
		return err
	}
	if err := sh.bin.Start(); err != nil {
		return err
	}
	return nil
}

func initSSH(host, user string, sh *shell) (err error) {
	defer func() {
		if err != nil {
			if sh.stdin != nil {
				sh.stdin.Close()
			}
			if sh.ssh != nil && sh.ssh.Session != nil {
				sh.ssh.Session.Close()
			}
		}
	}()

	if user == "" {
		user = os.Getenv("USER")
	}

	if sh.ssh, err = newSSHShell(host, user); err != nil {
		return err
	}
	if sh.stdin, err = sh.ssh.StdinPipe(); err != nil {
		return err
	}
	if sh.stdout, err = sh.ssh.StdoutPipe(); err != nil {
		return err
	}
	if sh.stderr, err = sh.ssh.StderrPipe(); err != nil {
		return err
	}
	if err = sh.ssh.Shell(); err != nil {
		return err
	}

	// scan motd
	if err = sh.run("echo"); err != nil {
		return err
	} else {
		sh.ssh.motd = string(sh.cmd.out)
	}
	return nil
}