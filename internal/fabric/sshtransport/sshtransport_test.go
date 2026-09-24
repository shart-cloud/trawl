package sshtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"trawl.cloud/trawl/internal/fabric"
)

func sshTestServer(t *testing.T) (string, []byte, *atomic.Int32) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var commands atomic.Int32
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				server, channels, requests, handshakeErr := ssh.NewServerConn(conn, config)
				if handshakeErr != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = server.Close() }()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					stream, reqs, channelErr := channel.Accept()
					if channelErr != nil {
						continue
					}
					for req := range reqs {
						if req.Type != "exec" {
							_ = req.Reply(false, nil)
							continue
						}
						commands.Add(1)
						_ = req.Reply(true, nil)
						_, _ = stream.Write([]byte("ok\n"))
						_, _ = stream.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						_ = stream.Close()
					}
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.MarshalAuthorizedKey(signer.PublicKey()), &commands
}

func TestDialVerifiesPinnedHostKeyBeforeAnyCommand(t *testing.T) {
	address, hostKey, commands := sshTestServer(t)
	device := fabric.Device{
		Address: address, Username: "monitor", Password: "test",
		SSHHostKey: hostKey,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runner, err := Dial(ctx, device)
	if err != nil {
		t.Fatalf("trusted host refused: %v", err)
	}
	output, err := runner.Run(ctx, "fixed-profile-command")
	_ = runner.Close()
	if err != nil || string(output) != "ok\n" {
		t.Fatalf("command result = %q, %v", output, err)
	}
	if commands.Load() != 1 {
		t.Fatalf("commands = %d, want 1", commands.Load())
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	device.SSHHostKey = ssh.MarshalAuthorizedKey(wrongSigner.PublicKey())
	if _, err := Dial(ctx, device); err == nil {
		t.Fatal("wrong host key was accepted")
	}
	if commands.Load() != 1 {
		t.Fatal("a command ran after host-key refusal")
	}
	device.SSHHostKey = append(hostKey, device.SSHHostKey...)
	if _, err := Dial(ctx, device); err == nil {
		t.Fatal("multiple host keys were accepted as one pin")
	}
}
