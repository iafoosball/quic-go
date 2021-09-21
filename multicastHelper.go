package quic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
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

func MultiCast(files chan string, conn *net.UDPConn, hclient *http.Client, addr net.Addr) {
	//s.logger.Infof("Started multicast: ")
	//s.MultiCast.Addr, s.UniCast.Addr
	fmt.Println("Multicasting helper")

	var wg sync.WaitGroup
	wg.Add(1)
	for {
		select {
		case file := <-files:
			fmt.Println(file)
			if !strings.Contains(file, "m3u8") {
				//url := "https://" + s.UniCast.Addr + "/" + file

				//conn.Write()

				success := getTest(file, conn, hclient, addr)
				if false {
					fmt.Println(success)
				}

			}
		default:
		}

	}
}

func getTest(file string, conn *net.UDPConn, hclient *http.Client, addr net.Addr) bool {
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
	testFile, err := os.Create(path.Base(url))
	if err != nil {
		fmt.Println("Error creating file", err)
	}
	fmt.Println(testFile)

	totalData := 0
	totalMulti := 0
	totalPackets := 0
	totalMultiPackets := 0
	now := time.Now()

	conn.SetWriteBuffer(protocol.InitialPacketSizeIPv4)
	go func() {
		//size := 32 * 1024

		//buf := make([]byte, size)
		buf := make([]byte, 1439)
		for {
			cont := true
			n, err := res.Body.Read(buf)
			if err != nil {
				if err == io.EOF {
					//testFile.Close()
					fmt.Println("total time ", time.Now().Sub(now))
					fmt.Println("Totaldata ", totalData, " Multi ", totalMulti, totalPackets, "/", totalMultiPackets)
					log.Fatal(err)
				} else {
					log.Fatal("ReadFromUDP failed:", err)
				}
			}

			if true {
				short := false
				if buf[0]&0x40 == 0 {
					fmt.Println("Would be error 0x40 ", n)
				} else if buf[0]&0x31 == 0 {
					fmt.Println("Would be error 0x31 ", n)
				} else if buf[0]&0x30 == 0 {
					fmt.Println("Would be error 0x30 ", n)
				} else {
					hdr, data, _, err := wire.ParsePacket(buf[:n], 0)
					if err != nil {
						//log.Panic(err)
						fmt.Println("Would be error 2", buf[0], n)
						cont = false
					}
					extHdr, err := unPackMultiShortHeaderPacket(hdr, time.Now(), data)
					if err != nil {
						fmt.Println("Would be error ", buf[0], n)
						//log.Panic(err)
						cont = false
					}
					if cont {
						fmt.Println(extHdr.PacketNumber)
					}
				}
				for i := 43; i < 60; i++ {
					if buf[i]&0x80 == 0 {
						short = true
						//	fmt.Printf(" %x ", buf[i])
					}

				}
				if !short {
					//fmt.Print("Not short header")
				} else if false {

				}
			}

			totalPackets += 1
			totalData += n
			/*

				f, err := os.Open(file)
				if err != nil {
					panic(err)
				}
				defer f.Close()

				d, err := f.Stat()
				if err != nil {
					panic(err)
				}
			*/
			conn.SetWriteDeadline(time.Now().Add(time.Millisecond * 500))
			m, _ := conn.Write(buf[0:n])
			time.Sleep(time.Millisecond * 1)
			totalMulti += m
			totalMultiPackets += 1
			_, ferr := testFile.Write(buf[0:n])
			if ferr != nil {
				log.Fatal("File error ", ferr)
			}
			if err == io.EOF {
				testFile.Close()
				break
			}
		}

		/*
			b := make(buf)
			n, err := res.Body.Read(buf)
			if err != nil {
				if err == io.EOF {
					//testFile.Close()
				} else {
					log.Fatal("ReadFromBody failed:", err)
				}
			}
			_, ferr := testFile.Write(buf[0:n])
			if ferr != nil {
				log.Fatal("File error ", ferr)
			}
			if err == io.EOF {
				testFile.Close()
				break
			}
		*/
		//fmt.Println("Written ", n)

	}()
	//pass := &PassThru{RemoteAddr: addr}
	/*
		_, err = io.Copy(testFile, res.Body)
		if err != nil {
			log.Fatal(err)
			return false
		}
	*/

	if res.StatusCode == 200 {
		fmt.Println("Received ", url, res.Header["Content-Length"])
		return true
	} else {
		fmt.Println("Error code ", res.StatusCode)
		return false
	}
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
	Reader io.Reader
	Writer io.Writer
	total  int64 // Total # of bytes transferred
	done   bool  // Total # of bytes transferred
	//File     *os.File
	buf        []byte // contents are the bytes buf[off : len(buf)]
	off        int    // read at &buf[off], write at &buf[len(buf)]
	RemoteAddr net.Addr
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
	fmt.Println("received ", n)
	//proccesedPacket, wh, err := c.session.handleMultiPacket(r)

	if int64(n) == pt.total {
		//pt.Reader.CancelRead(0)
		fmt.Println("Done pass")
		pt.done = true
	}
	return n, err
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
