package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/sanitize"
)

const (
	connectTimeout = 15 * time.Second
	commandTimeout = 15 * time.Second
	maxOutput      = 1 << 20
)

// Runner executes compiled profile commands over one verified SSH connection.
type Runner interface {
	Run(context.Context, string) ([]byte, error)
	Close() error
}

// Dial requires a pinned host key and Secret-held authentication.
func Dial(ctx context.Context, device fabric.Device) (Runner, error) {
	if len(device.SSHHostKey) == 0 {
		return nil, errors.New("device Secret is missing sshHostKey")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey(device.SSHHostKey)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: invalid sshHostKey", fabric.ErrUntrustedDevice)
	}
	if device.Username == "" {
		return nil, errors.New("device Secret is missing username")
	}
	var auth ssh.AuthMethod
	switch {
	case len(device.SSHPrivateKey) > 0:
		signer, parseErr := ssh.ParsePrivateKey(device.SSHPrivateKey)
		if parseErr != nil {
			return nil, errors.New("device Secret has an invalid sshPrivateKey")
		}
		auth = ssh.PublicKeys(signer)
	case device.Password != "":
		auth = ssh.Password(device.Password)
	default:
		return nil, errors.New("device Secret needs sshPrivateKey or password")
	}
	address := device.Address
	if address == "" {
		return nil, errors.New("device Secret is missing address")
	}
	if _, _, splitErr := net.SplitHostPort(address); splitErr != nil {
		if strings.Contains(splitErr.Error(), "missing port in address") {
			address = net.JoinHostPort(address, "22")
		} else {
			return nil, errors.New("device Secret has an invalid address")
		}
	}
	hostKeyFailed := false
	cfg := &ssh.ClientConfig{
		User: device.Username, Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(hostname string, remote net.Addr, offered ssh.PublicKey) error {
			if err := ssh.FixedHostKey(key)(hostname, remote, offered); err != nil {
				hostKeyFailed = true
				return err
			}
			return nil
		}, Timeout: connectTimeout,
	}
	conn, err := (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connecting to the device over SSH: %w", sanitize.Error(err))
	}
	if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		_ = conn.Close()
		return nil, errors.New("setting the SSH connection deadline failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	stop()
	if err != nil {
		_ = conn.Close()
		if hostKeyFailed {
			return nil, fabric.ErrUntrustedDevice
		}
		return nil, errors.New("SSH handshake or authentication failed")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return nil, errors.New("clearing the SSH connection deadline failed")
	}
	return &runner{client: ssh.NewClient(clientConn, chans, reqs), conn: conn}, nil
}

type runner struct {
	client *ssh.Client
	conn   net.Conn
}

func (r *runner) Close() error { return r.client.Close() }

func (r *runner) Run(ctx context.Context, command string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := r.conn.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return nil, errors.New("setting the SSH command deadline failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = r.client.Close() })
	defer stop()
	defer func() { _ = r.conn.SetDeadline(time.Time{}) }()
	session, err := r.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("opening an SSH session: %w", sanitize.Error(err))
	}
	defer func() { _ = session.Close() }()
	stdout := &boundedBuffer{max: maxOutput}
	stderr := &boundedBuffer{max: 16 << 10}
	session.Stdout, session.Stderr = stdout, stderr
	if err := session.Run(command); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("device command failed: %w", sanitize.Error(err))
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("device command output exceeded its limit")
	}
	return stdout.Bytes(), nil
}

type boundedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len()+len(p) > b.max {
		b.overflow = true
		return 0, errors.New("SSH output limit reached")
	}
	return b.buf.Write(p)
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}
