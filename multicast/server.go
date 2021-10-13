package multicast

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"github.com/iafoosball/quic-go/internal/ackhandler"
	"github.com/iafoosball/quic-go/internal/handshake"
	"github.com/iafoosball/quic-go/internal/protocol"
	"github.com/iafoosball/quic-go/internal/utils"
	"github.com/iafoosball/quic-go/logging"
	"github.com/iafoosball/quic-go/quicvarint"
	"golang.org/x/net/ipv4"
)

// Server is a mHTTP/3 Multicastserver.
type MulticastServer struct {
	*http3.Server
	Multicast  *http.Server
	QuicConfig *quic.Config
	port       uint32 // used atomically
	multiAddr  string

	mutex     sync.Mutex
	listeners map[*quic.EarlyListener]struct{}
	closed    utils.AtomicBool

	loggerOnce sync.Once
	logger     utils.Logger

	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler

	rttStats            *utils.RTTStats
	perspective         protocol.Perspective
	version             protocol.VersionNumber
	tracer              logging.ConnectionTracer
	RetransmissionQueue *quic.RetransmissionQueue

	ifat       *net.Interface
	RemoteAddr net.Addr
}

type sender interface {
	Send()
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

// allows mocking of quic.Listen and quic.ListenAddr
var (
	quicListen     = quic.ListenEarly
	quicListenAddr = quic.ListenAddrEarly
)

const (
	nextProtoH3Draft29 = "h3-29"
	nextProtoH3        = "h3"
)

const (
	streamTypeControlStream      = 0
	streamTypePushStream         = 1
	streamTypeQPACKEncoderStream = 2
	streamTypeQPACKDecoderStream = 3
)

type ConnPassTrough struct {
	*net.UDPConn
	DataWriteStream chan []byte
	DataReadStream  chan []byte
}

const message = "foobar"

const addr = "localhost:4242"

type loggingWriter struct{ io.Writer }

// Start a server that echos all data on the first stream opened by the client
func multicastServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	multiListener, err := quic.ListenAddr("224.42.42.1:1235", generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	multiSess, err := multiListener.Accept(context.Background())
	if err != nil {
		return err
	}
	sess, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}
	multiStream, err := multiSess.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	_, err = io.Copy(loggingWriter{multiStream}, stream)
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

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
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

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *MulticastServer) ListenAndServeTLSMultiFolder(certFile, keyFile, addr, multiACKAddr, multiAddr string, ifat *net.Interface, handler http.Handler, files chan string) error {
	var err error

	// Load certs
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}

	s.ifat = ifat
	//IGMP stuff here, init normal server, get packages generated by normal server
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
	p.Close()

	// Open the listeners
	mUdpAddr, err := net.ResolveUDPAddr("udp", multiAddr)
	if err != nil {
		return err
	}

	mUdpConn, err := net.DialUDP("udp", nil, mUdpAddr)
	if err != nil {
		return err
	}
	defer mUdpConn.Close()

	fmt.Println("mUDP ", multiAddr)
	s.multiAddr = multiAddr

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	// Open the listeners
	multiACKudpAddr, err := net.ResolveUDPAddr("udp", multiACKAddr)
	if err != nil {
		return err
	}
	multiACKudpConn, err := net.ListenUDP("udp", multiACKudpAddr)
	if err != nil {
		return err
	}
	defer multiACKudpConn.Close()

	readUDP := make(chan []byte)
	writeUDP := make(chan []byte)

	uConn := ConnPassTrough{
		udpConn,
		writeUDP,
		readUDP,
	}
	if false {
		fmt.Print(uConn)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, config)
	defer tlsConn.Close()

	// Start the servers
	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: config,
	}
	// Start the servers
	multihttpServer := &http.Server{
		Addr:      multiACKAddr,
		TLSConfig: config,
	}

	quicServer := &http3.Server{
		Server: httpServer,
	}

	multiACKquicServer := &http3.Server{
		Server: multihttpServer,
	}

	multicastServer := &MulticastServer{
		Server:    quicServer,
		Multicast: httpServer,
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}
	httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		w.Header().Add("multicast-ack", multiACKAddr)
		w.Header().Add("multicast", multiAddr)
		handler.ServeHTTP(w, r)
	})
	multiACKquicServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		w.Header().Add("multicast-ack", multiACKAddr)
		w.Header().Add("multicast", multiAddr)
		handler.ServeHTTP(w, r)
	})

	hErr := make(chan error)
	qErr := make(chan error)
	mErr := make(chan error)
	aErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()
	go func() {
		//	aErr <- multiACKquicServer.ListenACK(multiACKudpConn)
	}()
	go func() {
		mErr <- multicastServer.ServeFolder(mUdpConn, multiACKudpConn, files)
	}()

	go func() {
		select {
		case b := <-readUDP:
			fmt.Println(b)
		case b := <-writeUDP:
			fmt.Println(b)
		}
	}()

	s.rttStats = &utils.RTTStats{}
	s.RetransmissionQueue = quic.NewRetransmissionQueue(s.version)

	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		0,
		getMaxPacketSize(p.PacketConn.LocalAddr()),
		s.rttStats,
		s.perspective,
		s.tracer,
		s.logger,
		s.version,
	)

	select {
	case err := <-hErr:
		quicServer.Close()
		multicastServer.Close()
		multiACKquicServer.Close()
		return err
	case err := <-qErr:
		multicastServer.Close()
		multiACKquicServer.Close()
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	case err := <-mErr:
		quicServer.Close()
		multiACKquicServer.Close()
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	case err := <-aErr:
		quicServer.Close()
		multicastServer.Close()
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}

func (u ConnPassTrough) Write(b []byte) (int, error) {
	u.DataWriteStream <- b

	return u.UDPConn.Write(b)
}

func (u ConnPassTrough) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	u.DataWriteStream <- b

	return u.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (u ConnPassTrough) WriteTo(b []byte, addr net.Addr) (int, error) {
	u.DataWriteStream <- b

	return u.UDPConn.WriteTo(b, addr)
}

func (u ConnPassTrough) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	u.DataWriteStream <- b

	return u.UDPConn.WriteToUDP(b, addr)
}

func (u ConnPassTrough) Read(b []byte) (int, error) {
	u.DataReadStream <- b

	return u.UDPConn.Read(b)
}

func (u ConnPassTrough) ReadFrom(b []byte) (int, net.Addr, error) {
	u.DataReadStream <- b

	return u.UDPConn.ReadFrom(b)
}

func (u ConnPassTrough) ReadFromUDP(b []byte) (int, net.Addr, error) {
	u.DataReadStream <- b

	return u.UDPConn.ReadFromUDP(b)
}

func (u ConnPassTrough) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	u.DataReadStream <- b

	return u.UDPConn.ReadMsgUDP(b, oob)
}

func getMaxPacketSize(addr net.Addr) protocol.ByteCount {
	maxSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	// If this is not a UDP address, we don't know anything about the MTU.
	// Use the minimum size of an Initial packet as the max packet size.
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if utils.IsIPv4(udpAddr.IP) {
			maxSize = protocol.InitialPacketSizeIPv4
		} else {
			maxSize = protocol.InitialPacketSizeIPv6
		}
	}
	return maxSize
}

// Serve an existing UDP connection.
// It is possible to reuse the same connection for outgoing connections.
// Closing the server does not close the packet conn.
func (s *MulticastServer) ServeFolder(conn *net.UDPConn, ackConn *net.UDPConn, folder chan string) error {
	fmt.Println("Serve folder")
	return s.serveImpl(s.TLSConfig, conn, ackConn, folder)
}

func (s *MulticastServer) serveImpl(tlsConf *tls.Config, conn *net.UDPConn, ackConn *net.UDPConn, folder chan string) error {
	if s.closed.Get() {
		return http.ErrServerClosed
	}
	if s.Server == nil {
		return errors.New("use of http3.Server without http.Server")
	}
	s.loggerOnce.Do(func() {
		s.logger = utils.DefaultLogger.WithPrefix("multicastserver")
	})

	// The tls.Config we pass to Listen needs to have the GetConfigForClient callback set.
	// That way, we can get the QUIC version and set the correct ALPN value.
	baseConf := &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			// determine the ALPN from the QUIC version used
			proto := nextProtoH3Draft29
			if qconn, ok := ch.Conn.(handshake.ConnWithVersion); ok {
				if qconn.GetQUICVersion() == protocol.Version1 {
					proto = nextProtoH3
				}
			}
			config := tlsConf
			if tlsConf.GetConfigForClient != nil {
				getConfigForClient := tlsConf.GetConfigForClient
				var err error
				conf, err := getConfigForClient(ch)
				if err != nil {
					return nil, err
				}
				if conf != nil {
					config = conf
				}
			}
			if config == nil {
				return nil, nil
			}
			config = config.Clone()
			config.NextProtos = []string{proto}
			return config, nil
		},
	}

	var ln quic.EarlyListener
	var err error
	quicConf := s.QuicConfig
	if quicConf == nil {
		quicConf = &quic.Config{}
	} else {
		quicConf = s.QuicConfig.Clone()
	}
	if s.EnableDatagrams {
		quicConf.EnableDatagrams = true
	}
	ackConn.SetWriteBuffer(1436)
	if ackConn == nil {
		fmt.Println("Conn nil ")
		ln, err = quicListenAddr(s.multiAddr, baseConf, quicConf)
	} else {
		ln, err = quicListen(ackConn, baseConf, quicConf)
	}
	if err != nil {
		return err
	}
	log.Println("Serve multi on ", s.multiAddr, " ", ln)

	go s.multiCast(conn, folder)

	for {

		sess, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		fmt.Println("So far so good")

		go s.handleACK(sess, ackConn)
		//go s.handleConn(sess)
	}
}

const settingDatagram = 0x276

type settingsFrame struct {
	Datagram bool
	other    map[uint64]uint64 // all settings that we don't explicitly recognize
}

func (f *settingsFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, 0x4)
	var l protocol.ByteCount
	for id, val := range f.other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	quicvarint.Write(b, uint64(l))
	if f.Datagram {
		quicvarint.Write(b, settingDatagram)
		quicvarint.Write(b, 1)
	}
	for id, val := range f.other {
		quicvarint.Write(b, id)
		quicvarint.Write(b, val)
	}
}

func (s *MulticastServer) handleACK(sess quic.Session, ackConn *net.UDPConn) {

	str, err := sess.OpenUniStream()
	if err != nil {
		s.logger.Debugf("Opening the control stream failed.")
		return
	}
	buf := &bytes.Buffer{}
	quicvarint.Write(buf, streamTypeControlStream) // stream type
	(&settingsFrame{Datagram: s.EnableDatagrams}).Write(buf)
	n, err := str.Write(buf.Bytes())
	fmt.Println("n ", n, " err ", err)

	ackbuf := make([]byte, 1439)

	fmt.Println("HandleACK")
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			panic(err)
		} else {
			fmt.Println("herre")
		}
		buf := make([]byte, 1439)
		binary.LittleEndian.PutUint16(buf, 0)
		bw := bufio.NewWriter(stream)

		go func() {
			n, err := bw.Write([]byte("Welcome"))
			if err != nil {
				fmt.Println("Stream write err  ", err)

			}
			bw.Flush()
			fmt.Println("Stream open ", n)

			for {
				r, err := stream.Read(ackbuf)
				if err != nil {
					panic(err)
				}
				if ackbuf[0] == 0x35 {
					bw.WriteByte(0x36)
					bw.Flush()
				}
				if ackbuf[0] == 0x33 {
					fmt.Println("Data from ack: ", hex.EncodeToString(ackbuf[:r]))

					for i := 1; i < len(ackbuf[1:r]); i += 2 {
						packetNumber := binary.LittleEndian.Uint16(ackbuf[i : i+2])
						quic.Retransmit(bw, packetNumber)
					}

				} else {

				}
			}
		}()
	}
}

func (s *MulticastServer) multiCast(conn *net.UDPConn, files chan string) {
	s.logger.Infof("Started multicast here: ")
	//s.MultiCast.Addr, s.UniCast.Addr

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}

	tlsconf := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}
	/*
		roundTripper := &RoundTripper{
			Ifat:            s.ifat,
			MultiAddr:       s.Multicast.Addr,
			TLSClientConfig: tlsconf,
			QuicConfig:      s.QuicConfig,
		}
	*/
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsconf,
		QuicConfig:      s.QuicConfig,
	}

	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
	}

	go quic.MultiCast(files, conn, hclient, s.RemoteAddr)

}

func getTest(file string, hclient *http.Client) bool {
	url := file
	fmt.Println("Sending ", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error ", err)
		return false
	}
	req.Header.Set("Multicast", "true")
	res, err := hclient.Do(req)
	if err != nil {
		log.Fatal(err)
		return false
	}

	pass := &PassThru{}
	written, err := io.Copy(pass, res.Body)
	if err != nil {
		log.Fatal(err)
		return false
	}

	if res.StatusCode == 200 {
		fmt.Println("Received ", url, written, res.Header["Content-Length"])
		return true
	} else {
		fmt.Println("Error code ", res.StatusCode)
		return false
	}
}

type PassThru struct {
	Reader io.Reader
	Writer io.Writer
	total  int64 // Total # of bytes transferred
	done   bool  // Total # of bytes transferred
	//File     *os.File
	buf []byte // contents are the bytes buf[off : len(buf)]
	off int    // read at &buf[off], write at &buf[len(buf)]
}

func (pt *PassThru) Write(p []byte) (int, error) {
	var err error
	pt.total += int64(len(p))
	//fmt.Println("Read", p, "bytes for a total of", pt.total)

	return len(p), err
}

func (pt *PassThru) Read(p []byte) (int, error) {
	n, err := pt.Reader.Read(p)
	if err == nil {
		pt.total += int64(n)
		fmt.Println("Read", n, "bytes for a total of", pt.total)
	}

	if int64(n) == pt.total {
		//pt.Reader.CancelRead(0)
		fmt.Println("Done pass")
		pt.done = true
	}
	return n, err
}
