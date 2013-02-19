// Copyright 2013 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package spipe

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
)

var (
	clientTestBytes = []byte("Hello from client!")
	serverTestBytes = []byte("Hello from server!")
)

func launchServer(t *testing.T, ln net.Listener, done chan<- bool) {
	s, err := ln.Accept()
	defer s.Close()
	if err != nil {
		t.Fatalf("server accept: %s", err)
	}
	fmt.Println("server read")
	test := make([]byte, len(clientTestBytes))
	_, err = io.ReadFull(s, test[:])
	if err != nil {
		t.Fatalf("server read: %s", err)
	}
	if !bytes.Equal(test, clientTestBytes) {
		t.Fatalf("server: received wrong test bytes")
	}
	fmt.Println("server write")
	_, err = s.Write(serverTestBytes)
	if err != nil {
		t.Fatalf("server write test bytes: %s", err)
	}
	s.Close()
	done <- true
}

func TestClientServer(t *testing.T) {
	key := []byte("secret key")

	ln, err := Listen(key, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server listen: %s", err)
	}
	fmt.Printf("listening on %s\n", ln.Addr())
	defer ln.Close()
	serverDone := make(chan bool)
	go launchServer(t, ln, serverDone)

	fmt.Println("connecting")
	c, err := Dial(key[:], "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %s", err)
	}
	fmt.Println("client writing")
	_, err = c.Write(clientTestBytes)
	if err != nil {
		t.Fatalf("client write test bytes: %s", err)
	}
	test := make([]byte, len(serverTestBytes))
	_, err = io.ReadFull(c, test[:])
	if !bytes.Equal(test, serverTestBytes) {
		t.Fatalf("client: received wrong test bytes")
	}
	err = c.Close()
	if err != nil {
		t.Fatalf("client close: %s", err)
	}
	fmt.Println("client done")
	<-serverDone
	fmt.Println("server done")
}
