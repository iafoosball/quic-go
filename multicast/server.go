package multicast

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"golang.org/x/net/ipv4"
)

// Server is a mHTTP/3 Multicastserver.
type Server struct {
	*http.Server

	http3      http3.Server
	QuicConfig *quic.Config
	port       uint32 // used atomically

}

const (
	nextProtoH3Draft29 = "h3-29"
	nextProtoH3        = "h3"
)

type ConnPassTrough struct {
	*net.UDPConn
	DataWriteStream chan []byte
	DataReadStream  chan []byte
}

// ListenAndServeTLS listens on the UDP address s.Addr and calls s.Handler to handle HTTP/3 requests on incoming connections.
func (s *Server) ListenAndServeTLSMultiFolder(certFile string, keyFile string, addr string, multiAddr string, handler http.Handler) error {
	var err error
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

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		panic(err)
	}

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifat, &net.UDPAddr{IP: group, Port: port}); err != nil {
		// error handling
		println("Error #2 " + err.Error())
	} else {
		println("Joined IGMP")
	}

	defer p.Close()

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

	readUDP := make(chan []byte)
	writeUDP := make(chan []byte)

	uConn := ConnPassTrough{
		udpConn,
		writeUDP,
		readUDP,
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

	quicServer := &http3.Server{
		Server: httpServer,
	}

	multicastServer := &http3.Server{
		Server: httpServer,
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}
	httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		w.Header().Add("multicast", multiAddr)
		handler.ServeHTTP(w, r)
	})

	hErr := make(chan error)
	qErr := make(chan error)
	mErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()
	go func() {
		qErr <- quicServer.Serve(uConn)
	}()
	go func() {
		mErr <- multicastServer.Serve(p.PacketConn)
	}()

	go func() {
		select {
		case b := <-readUDP:
			fmt.Println(b)
		case b := <-writeUDP:
			fmt.Println(b)
		}
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		multicastServer.Close()
		return err
	case err := <-qErr:
		multicastServer.Close()
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	case err := <-mErr:
		quicServer.Close()
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}

/*

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
*/
