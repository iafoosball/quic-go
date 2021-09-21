package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"time"

	quic "github.com/iafoosball/quic-go"
	"golang.org/x/net/ipv4"
)

const addr = "localhost:4242"
const multiAddr = "224.42.42.1:1235"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	go func() { log.Fatal(echoServer()) }()

	err := clientMain()
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		return err
	}

	c, err := net.ListenPacket("udp4", multiAddr)
	if err != nil {
		println("Error #1 " + err.Error())
	}

	defer c.Close()
	mHost, mPort, err := net.SplitHostPort(multiAddr)
	if err != nil {
		println("Split host error " + err.Error())
	}

	group := net.ParseIP(mHost)
	port, err := strconv.Atoi(mPort)
	if err != nil {
		return err
	}

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifat, &net.UDPAddr{IP: group, Port: port}); err != nil {
		// error handling
		println("Error #2 " + err.Error())
	} else {
		println("Joined IGMP")
	}

	defer p.Close()

	go func() {

		multiListener, err := quic.ListenMulti(p.PacketConn, generateTLSConfig(), nil)
		if err != nil {
			panic(err)

		}
		defer multiListener.Close()

		multiSess, err := multiListener.Accept(context.Background())
		if err != nil {
			panic(err)

		} else {
			fmt.Println("Should be accepted")
		}
		_, err = multiSess.AcceptStream(context.Background())
		if err != nil {
			panic(err)
		}
	}()

	multiListener2, err := quic.Dial(p.PacketConn, p.LocalAddr(), addr, generateTLSConfig(), &quic.Config{})
	if err != nil {
		return err
	}

	multiStream2, err := multiListener2.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	defer multiStream2.Close()

	n, err := multiStream2.Write([]byte("Testing if open"))
	if err != nil {
		fmt.Println("Error writting multi ", err)
	}
	fmt.Println("Wrote test multi ", n)

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	sess, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}

	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}

	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	if err != nil {
		fmt.Println("Err ", err)
	}
	_, err = io.Copy(loggingWriter{multiStream2}, stream)
	return err
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	for i := 0; i < 10; i++ {
		num := strconv.Itoa(i)
		m := message + num
		fmt.Printf("Client: Sending '%s'\n", m)
		_, err = stream.Write([]byte(m))
		if err != nil {
			return err
		}

		buf := make([]byte, len(m))
		_, err = io.ReadFull(stream, buf)
		if err != nil {
			return err
		}
		fmt.Printf("Client: Got '%s'\n", buf)
		time.Sleep(time.Millisecond * 200)
	}

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
