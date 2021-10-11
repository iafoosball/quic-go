package quic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iafoosball/quic-go/internal/handshake"
	"github.com/iafoosball/quic-go/internal/protocol"
	"github.com/iafoosball/quic-go/internal/utils"
	"github.com/iafoosball/quic-go/internal/wire"
	"github.com/iafoosball/quic-go/logging"
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

var pt *PassThru

func MultiCast(files chan string, conn *net.UDPConn, hclient *http.Client, addr net.Addr) {
	//s.logger.Infof("Started multicast: ")
	//s.MultiCast.Addr, s.UniCast.Addr
	fmt.Println("Multicasting helper")

	totalPackets = 0
	packetNumber = 0
	packetHistory := make(map[uint16][]byte)
	var mu sync.Mutex
	conn.SetWriteBuffer(1436)
	pt = &PassThru{}
	pt.UDPConn = conn
	pt.Packet = 0
	pt.PacketHistory = packetHistory

	bw := bufio.NewWriter(pt)
	for {
		select {
		case file := <-files:
			fmt.Println(file)
			mu.Lock()
			success := getTest(file, bw, hclient, addr)
			fmt.Println("Got file ", file)
			mu.Unlock()
			if !success {
				fmt.Println("Big fail " + file)
			}
		default:
		}

	}
}

type MulticastHeader struct {
	wire.Header

	typeByte byte

	PacketNumberLen protocol.PacketNumberLen
	PacketNumber    protocol.PacketNumber

	parsedLen protocol.ByteCount
}

func (p *packetPacker) getMultiHeader() *MulticastHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	hdr := &MulticastHeader{}
	hdr.PacketNumber = pn
	hdr.PacketNumberLen = pnLen
	hdr.DestConnectionID = p.getDestConnID()
	return hdr
}

type simplePacket struct {
	PacketNumber uint16
	Data         []byte
	Buf          bytes.Buffer
}

var totalPackets uint64
var packetNumber uint16

func getTest(file string, bw *bufio.Writer, hclient *http.Client, addr net.Addr) bool {
	url := file
	request := true

	var totalData int64
	totalData = 0
	var m int64
	var statuscode int
	var filesize interface{}
	//totalMulti := 0
	totalMultiPackets := 0
	now := time.Now()

	totalPackets += 1
	packetNumber += 1

	//go func() {
	size := 1 * 1436

	buf := make([]byte, size)
	if !strings.Contains(file, "https://") {
		request = false

		fileStat, err := os.Open(file)
		if err != nil {

		}
		info, err := fileStat.Stat()
		if err != nil {

		}
		filesize = info.Size()
		bw.WriteByte(0x32)

		split := strings.Split(file, "//")
		filename := file
		if len(split) > 1 {
			filename = split[1]
		}

		fmt.Println(file)

		header := http.Header{}
		header.Add("Accept-Ranges", "bytes")
		header.Add("Filename", filename)
		header.Add("Content-Length", strconv.Itoa(int(info.Size())))
		header.Add("Multicast", "true")
		header.Add("Content-Type", "text/vnd.qt.linguist; charset=utf-8")
		header.Add("Accept-Ranges", "bytes")
		header.Add("Filename", filename)
		header.Add("Content-Length", strconv.Itoa(int(info.Size())))
		header.Add("Multicast", "true")
		header.Add("Content-Type", "text/vnd.qt.linguist; charset=utf-8")

		bw.WriteByte(0x32)
		for name, value := range header {
			fmt.Printf("%v: %v\n", name, value)
			for _, v := range value {
				bw.Write([]byte(name))
				bw.Write([]byte(": "))
				bw.Write([]byte(v))
				bw.Write([]byte("\r\n"))
			}
		}

		bw.Flush()
		packetNumber += 1

		bs := make([]byte, 2)
		multicaster := &Multicaster{bw, bs, packetNumber}
		m, err = copyBuffer(multicaster, fileStat, buf)
		if err != nil {
			log.Fatal(err)
			return false
		}
		totalData += m
		totalPackets += uint64(multicaster.Packet)
		packetNumber = multicaster.Packet

		fileStat.Close()
		//write empty packet if last packet was lost
		for i := 0; i < 0; i++ {

			packetNumber++
			bw.WriteByte(0x30)
			binary.LittleEndian.PutUint16(bs, packetNumber)

			bw.Write(bs)

			pt.PacketHistory[packetNumber] = []byte(string(""))
			pt.Packet = packetNumber
			totalPackets += 1
			bw.Flush()
		}
		statuscode = 200
	}
	if request {

		tempfile := strings.ReplaceAll(url, "https://", "")
		file = ""
		for i, s := range strings.Split(tempfile, "/") {
			if i > 0 {
				file = file + "/" + s

			}
		}
		file = file[1:]
		fmt.Println(file)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error ", err)
			return false
		}
		req.Header.Add("Multicast", "true")
		res, err := hclient.Do(req)
		if err != nil {
			log.Fatal(err)
			return false
		}
		srcConnID, err := generateConnectionID(4)
		if err != nil {
			panic(err)
		}
		destConnID, err := generateConnectionIDForInitial()
		if err != nil {
			panic(err)
		}

		fmt.Println("src id ", srcConnID, "dst id ", destConnID, " addr ", addr)

		filesize = res.Header["Content-Length"]
		mHeaderClone := res.Header.Clone()
		mHeaderClone.Add("Filename", file)
		mHeaderClone.Add("Filename", file)

		mHeaderClone.Write(bw)

		bw.WriteByte(0x32)
		for name, value := range mHeaderClone {
			fmt.Printf("%v: %v\n", name, value)
			for _, v := range value {
				bw.Write([]byte(name))
				bw.Write([]byte(": "))
				bw.Write([]byte(v))
				bw.Write([]byte("\r\n"))
			}
		}
		bw.Flush()

		bs := make([]byte, 2)
		multicaster := &Multicaster{bw, bs, packetNumber}
		m, err = copyBuffer(multicaster, res.Body, buf)
		if err != nil {
			log.Fatal(err)
			return false
		}

		//write empty packet if last packet was lost
		for i := 0; i < 0; i++ {

			packetNumber++
			bw.WriteByte(0x30)
			binary.LittleEndian.PutUint16(bs, packetNumber)

			bw.Write(bs)

			pt.PacketHistory[packetNumber] = []byte{}
			pt.Packet = packetNumber
			totalPackets += 1
			bw.Flush()
		}

		statuscode = res.StatusCode
		totalData += m
		totalPackets += uint64(multicaster.Packet)
		packetNumber = multicaster.Packet
		defer res.Body.Close()
	}

	totalTime := time.Now().Sub(now)
	var rate float64

	rate = (float64(totalData) / totalTime.Seconds()) / math.Pow(10, 6)
	fmt.Println("total time ", totalTime, " in ", rate, " MB/s")
	fmt.Println("Totaldata ", totalData, " Multi ", m, totalPackets, "/", totalMultiPackets)

	if statuscode == 200 {
		fmt.Println("Received ", file, " ", filesize)
		return true
	} else {
		fmt.Println("Error code ", statuscode)
		return false
	}
}

type Multicaster struct {
	Pass      *bufio.Writer
	PacketBuf []byte
	Packet    uint16
}

func (m *Multicaster) Write(p []byte) (int, error) {
	//var err error
	//pt.total += int64(len(p))
	//fmt.Println("Read", p, "bytes for a total of", pt.total)

	m.Pass.WriteByte(0x30)
	binary.LittleEndian.PutUint16(m.PacketBuf, m.Packet)

	m.Pass.Write(m.PacketBuf)
	n, err := m.Pass.Write(p)
	if err != nil {
		return n, err
	}
	//pt.PacketHistory[m.Packet] = []byte(string(p))
	pt.Packet = m.Packet
	m.Packet += 1
	m.Pass.Flush()

	return n, err
}

//Buffer from io.Copy
func copyBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrUnexpectedEOF
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func UnpackMulti(hdr *wire.Header, rcvTime time.Time, data []byte) (*unpackedPacket, error) {
	var encLevel protocol.EncryptionLevel
	var extHdr *wire.ExtendedHeader
	var decrypted []byte
	//nolint:exhaustive // Retry packets can't be unpacked.
	switch hdr.Type {
	default:
		if hdr.IsLongHeader {
			return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
		}
		encLevel = protocol.Encryption1RTT

		extHdr, err := unPackMultiShortHeaderPacket(hdr, rcvTime, data)
		if err != nil {
			return nil, err
		}
		fmt.Println(extHdr)
	}

	return &unpackedPacket{
		hdr:             extHdr,
		packetNumber:    extHdr.PacketNumber,
		encryptionLevel: encLevel,
		data:            decrypted,
	}, nil
}

var largestRcvdPacketNumber protocol.PacketNumber

func unPackMultiShortHeaderPacket(
	hdr *wire.Header,
	rcvTime time.Time,
	data []byte,
) (*wire.ExtendedHeader, error) {
	extHdr, parseErr := unpackMultiHeader(hdr, data, protocol.VersionDraft29)
	// If the reserved bits are set incorrectly, we still need to continue unpacking.
	// This avoids a timing side-channel, which otherwise might allow an attacker
	// to gain information about the header encryption.
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, parseErr
	}
	extHdr.PacketNumber = protocol.DecodePacketNumber(
		extHdr.PacketNumberLen,
		largestRcvdPacketNumber,
		extHdr.PacketNumber,
	)

	if parseErr != nil {
		return nil, parseErr
	}
	return extHdr, nil
}

func unpackMultiHeader(hdr *wire.Header, data []byte, version protocol.VersionNumber) (*wire.ExtendedHeader, error) {
	r := bytes.NewReader(data)

	hdrLen := hdr.ParsedLen()
	if protocol.ByteCount(len(data)) < hdrLen+4+16 {
		//nolint:stylecheck
		fmt.Println(data)
		return nil, fmt.Errorf("Packet too small. Expected at least 20 bytes after the header, got %d", protocol.ByteCount(len(data))-hdrLen)
	}
	// The packet number can be up to 4 bytes long, but we won't know the length until we decrypt it.
	// 1. save a copy of the 4 bytes
	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])

	// 3. parse the header (and learn the actual length of the packet number)
	extHdr, parseErr := hdr.ParseExtended(r, version)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != protocol.PacketNumberLen4 {
		copy(data[extHdr.ParsedLen():hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}
	return extHdr, parseErr
}

type PassThru struct {
	*net.UDPConn
	io.Reader
	Packet        uint16
	PacketHistory map[uint16][]byte
	mu            sync.Mutex
}

func (pt *PassThru) retransmit(str *bufio.Writer, number uint16) {
	pt.mu.Lock()
	p := pt.PacketHistory[number]
	//for i, p := range pt.PacketHistory {
	if len(pt.PacketHistory[number]) > 0 {
		fmt.Println("Data ", hex.EncodeToString(p[0:100]))
		fmt.Println("Number ", number, " pn ", binary.LittleEndian.Uint16(p[1:3]))
		p[0] = 0x34
		str.Write(p)
		str.Flush()
	}
	pt.mu.Unlock()
	//}
}

func (pt *PassThru) Write(p []byte) (int, error) {
	//var err error
	//pt.total += int64(len(p))
	//fmt.Println("Read", p, "bytes for a total of", pt.total)
	pt.mu.Lock()
	n, err := pt.UDPConn.Write(p)
	if err == nil {
		pt.PacketHistory[pt.Packet] = []byte(string(p))
	}
	pt.mu.Unlock()

	return n, err
}

func (pt *PassThru) Read(p []byte) (int, error) {

	n, err := pt.Reader.Read(p)
	if err != nil {
		return n, err
	}
	fmt.Println("received ", n)
	return n, err
}

func Retransmit(str *bufio.Writer, number uint16) {
	fmt.Println("Retransmit ", number)

	pt.retransmit(str, number)
}

func ListenMulti(conn net.PacketConn, tlsConf *tls.Config, config *Config) (Listener, error) {
	return listenMulti(conn, tlsConf, config, false)
}

func listenMulti(conn net.PacketConn, tlsConf *tls.Config, config *Config, acceptEarly bool) (*baseServer, error) {
	fmt.Println("Multicast session")
	if tlsConf == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	config = populateServerConfig(config)
	for _, v := range config.Versions {
		if !protocol.IsValidVersion(v) {
			return nil, fmt.Errorf("%s is not a valid QUIC version", v)
		}
	}

	sessionHandler, err := getMultiplexer().AddConn(conn, config.ConnectionIDLength, config.StatelessResetKey, config.Tracer)
	if err != nil {
		return nil, err
	}
	tokenGenerator, err := handshake.NewTokenGenerator(rand.Reader)
	if err != nil {
		return nil, err
	}
	c, err := wrapConn(conn)
	if err != nil {
		return nil, err
	}
	s := &baseServer{
		conn:                c,
		tlsConf:             tlsConf,
		config:              config,
		tokenGenerator:      tokenGenerator,
		sessionHandler:      sessionHandler,
		sessionQueue:        make(chan quicSession),
		errorChan:           make(chan struct{}),
		running:             make(chan struct{}),
		receivedPackets:     make(chan *receivedPacket, protocol.MaxServerUnprocessedPackets),
		newSession:          newSession,
		logger:              utils.DefaultLogger.WithPrefix("server"),
		acceptEarlySessions: acceptEarly,
	}

	s.multicastSetup()
	go s.run()
	sessionHandler.SetServer(s)
	s.logger.Debugf("Listening for %s connections on %s", conn.LocalAddr().Network(), conn.LocalAddr().String())
	return s, nil
}

func (s *baseServer) multicastSetup() (Stream, error) {
	var str Stream
	p := &receivedPacket{
		buffer:     getPacketBuffer(),
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("224.42.42.1"), Port: 1235},
		rcvTime:    time.Now(),
	}
	destConnectionID, err := protocol.GenerateConnectionID(s.config.ConnectionIDLength)
	if err != nil {
		return str, err
	}
	srcConnectionID, err := protocol.GenerateConnectionID(s.config.ConnectionIDLength)
	if err != nil {
		return str, err
	}
	hdr := &wire.Header{
		IsLongHeader:     false,
		DestConnectionID: destConnectionID,
		SrcConnectionID:  srcConnectionID,
		Type:             protocol.PacketType0RTT,
	}

	var (
		retrySrcConnID *protocol.ConnectionID
	)
	origDestConnID := hdr.DestConnectionID

	connID, err := protocol.GenerateConnectionID(s.config.ConnectionIDLength)
	if err != nil {
		return str, err
	}
	s.logger.Debugf("Changing connection ID to %s.", connID)
	var sess quicSession
	tracingID := nextSessionTracingID()
	if added := s.sessionHandler.AddWithConnID(hdr.DestConnectionID, connID, func() packetHandler {
		var tracer logging.ConnectionTracer
		if s.config.Tracer != nil {
			// Use the same connection ID that is passed to the client's GetLogWriter callback.
			connID := hdr.DestConnectionID
			if origDestConnID.Len() > 0 {
				connID = origDestConnID
			}
			tracer = s.config.Tracer.TracerForConnection(
				context.WithValue(context.Background(), SessionTracingKey, tracingID),
				protocol.PerspectiveServer,
				connID,
			)
		}
		sess = s.newSession(
			newSendConn(s.conn, p.remoteAddr, p.info),
			s.sessionHandler,
			origDestConnID,
			retrySrcConnID,
			hdr.DestConnectionID,
			hdr.SrcConnectionID,
			connID,
			s.sessionHandler.GetStatelessResetToken(connID),
			s.config,
			s.tlsConf,
			s.tokenGenerator,
			s.acceptEarlySessions,
			tracer,
			tracingID,
			s.logger,
			hdr.Version,
		)
		sess.handlePacket(p)
		return sess
	}); !added {
		return str, nil
	}

	go sess.run()
	go s.handleNewMultiSession(sess)
	str, err = sess.AcceptStream(context.Background())
	if sess == nil {
		p.buffer.Release()
		return str, nil
	}
	return str, nil
}

func (s *baseServer) handleNewMultiSession(sess quicSession) {
	sessCtx := sess.Context()

	fmt.Println("So far so good")
	atomic.AddInt32(&s.sessionQueueLen, 1)
	select {
	case s.sessionQueue <- sess:
		fmt.Println("Here we go")
		// blocks until the session is accepted
	case <-sessCtx.Done():
		atomic.AddInt32(&s.sessionQueueLen, -1)
		// don't pass sessions that were already closed to Accept()
	}
}

// Accept returns sessions that already completed the handshake.
// It is only valid if acceptEarlySessions is false.
func (s *baseServer) MultiAccept(ctx context.Context) (Session, error) {
	return s.multiAccept(ctx)
}

func (s *baseServer) multiAccept(ctx context.Context) (quicSession, error) {
	fmt.Println("Accepted multi called")
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case sess := <-s.sessionQueue:
		fmt.Println("Accepted multi ", sess)
		atomic.AddInt32(&s.sessionQueueLen, -1)
		return sess, nil
	case <-s.errorChan:
		return nil, s.serverError
	}
}
