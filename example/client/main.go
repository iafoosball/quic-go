package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"github.com/iafoosball/quic-go/internal/testdata"
	"github.com/iafoosball/quic-go/internal/utils"
	"github.com/iafoosball/quic-go/logging"
	"github.com/iafoosball/quic-go/multicast"
	"github.com/iafoosball/quic-go/qlog"
)

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}
func echoServer(addr string) error {
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
	return err
}

func clientMain(message, addr string) error {
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

var filename *string
var bw *bufio.Writer

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	hostString := flag.String("h", "192.168.42.52:1234", "host string")
	multiAddr := flag.String("m", "224.42.42.1:1235", "host string")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	urls := flag.Args()
	if true {
		urls = []string{"https://" + *hostString + "/index.m3u8", "https://" + *hostString + "/index0.ts", "https://" + *hostString + "/index1.ts", "https://" + *hostString + "/index2.ts", "https://" + *hostString + "/index3.ts", "https://" + *hostString + "/index4.ts", "https://" + *hostString + "/index5.ts", "https://" + *hostString + "/index6.ts"}
	}

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("client_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	ifat, err := net.InterfaceByIndex(2)
	if err != nil {
		return
	}

	tlsConf := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: *insecure,
		KeyLogWriter:       keyLog,
	}

	roundTripperHttp3 := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      &qconf,
	}
	roundTripper := &multicast.RoundTripper{
		RoundTripper: roundTripperHttp3,
		MultiAddr:    *multiAddr,
		Ifat:         ifat,
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}

	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}
	if false {
		fmt.Println(hclient, urls, quiet)
	}
	//Can be used for faststart
	//var wg sync.WaitGroup
	//wg.Add(len(urls))
	/*
		for _, addr := range urls {
			logger.Infof("GET %s", addr)
			//go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Fatal(err)
			}
			logger.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				logger.Infof("Response Body: %d bytes", body.Len())
			} else {
				logger.Infof("Response Body:")
				logger.Infof("%s", body.Bytes())
			}
			//wg.Done()
			//}(addr)
		}
	*/

	c, err := net.ListenPacket("udp4", "224.42.42.1:1235")
	if err != nil {
		// error handling
		println("Error listen unicast " + err.Error())
	}
	defer c.Close()

	addr, err := net.ResolveUDPAddr("udp", "224.42.42.1:1235")
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	size := 32 * 1024
	databuf := make([]byte, size)
	l.SetReadBuffer(size)

	var testFile *os.File

	totalPackets := 0
	totalSize := int64(0)

	packets = make(map[string]*packetDetails)
	doneChan := make(chan error, 1)
	ctx := context.Background()

	now := time.Now()
	pn := 0

	done := false
	started := false

	//	go func() { log.Fatal(echoServer(*hostString)) }()
	/*
		err = clientMain(message, *hostString)
		if err != nil {
			panic(err)
		}
	*/
	tlsConf2 := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	session, err := quic.DialAddr(*hostString, tlsConf2, nil)
	if err != nil {
		panic(err)
	}

	var ackStr quic.Stream

	ackBuf := make([]byte, 1439)
	go func() {

		ackStr, err = session.OpenStreamSync(context.Background())
		if err != nil {
			panic(err)
		}

		bw = bufio.NewWriter(ackStr)

		bw.Write([]byte("Hello"))
		bw.Flush()

		fmt.Println("stream open ")
		for {
			n, err := ackStr.Read(ackBuf)
			if err != nil {
				if err.Error() == "deadline exceeded" {
					fmt.Println("Done with this packet for segment ", *filename)
					saveFile(*filename)
					ackStr.SetReadDeadline(time.Now().Add(time.Second * 120))
				} else {
					panic(err)
				}
			}

			if ackBuf[0] == 0x33 || ackBuf[0] == 0x34 && n > 0 {
				ackStr.SetReadDeadline(time.Now().Add(time.Second * 1))
				totalSize = processDataPacket(ackBuf, n, totalSize)
			} else if n > 0 && n < 100 {
				fmt.Println(string(ackBuf[:n]))
			}
		}
	}()

	name := ""

	go func() {

		for {

			n, err := l.Read(databuf)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					lost := checkLostPackets(packets[name], bw)
					if lost > 0 {
						bw.Flush()
						fmt.Println()
					} else {
						saveFile(name)
					}
					fmt.Println("Lost packets #1 ", lost, " with ", name)
					packets[name].Done = true
					done = true
					n = pn
				} else {
					doneChan <- err
					break
				}
			} else {
				l.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
				pn = n
			}
			if totalPackets == 0 {
				now = time.Now()
			}
			if databuf[0]&0x32 == 0 || databuf[0] == 0x32 {
				fmt.Println("Header")
				if started {
					pPacket := packets[name]
					if !pPacket.Done {
						fmt.Println("Packet check ", name, " L ", pPacket.ContentLength, " A ", pPacket.ActualLenght)

						//Check if previously file got everything
						lost := checkLostPackets(packets[name], bw)
						if lost > 0 {
							bw.Flush()
							fmt.Println()
						} else {
							saveFile(name)
						}
						fmt.Println("Lost packets #2 ", lost, " with ", name)
					}
				}
				started = true

				reader := bufio.NewReader(strings.NewReader(string(databuf[0:n]) + "\r\n"))
				tp := textproto.NewReader(reader)

				mimeHeader, err := tp.ReadMIMEHeader()
				if err != nil {
					log.Fatal(err)
				}

				// http.Header and textproto.MIMEHeader are both just a map[string][]string
				httpHeader := http.Header(mimeHeader)
				log.Println(httpHeader)
				name = "video/" + httpHeader.Get("filename")
				fmt.Println(name, " ", httpHeader.Get("Content-Length"))

				err = ensureDir(path.Dir(name))
				if err != nil {
					panic(err)
				}

				filename = &name

				contentLenght, err := strconv.Atoi(httpHeader.Get("Content-Length"))
				packets[name] = &packetDetails{
					Lowest:        65535,
					Highest:       0,
					ContentLength: contentLenght,
					ActualLenght:  0,
					All:           make(map[uint16][]byte),
					Done:          false,
					Name:          name,
					mu:            sync.Mutex{},
				}

			} else if (databuf[0] == 0x30 || databuf[0]&0x30 == 0 || databuf[0]&0x31 == 0) && started {
				totalPackets++

				totalSize = processDataPacket(databuf, pn, totalSize)

			} else if !started {
				fmt.Println("first ", hex.EncodeToString(databuf[:pn]))
				fmt.Println(databuf[0])
				fmt.Println(databuf[0] == 0x32)
				fmt.Println(databuf[0] & 0x32)
				started = true
			}
			if done {

				l.SetReadDeadline(time.Now().Add(time.Second * 30))
				//testFile.Close()
				done = false
			}

			//dst.Write(buf[:n])

			/*

				data, err := ioutil.ReadAll(l)
				if err != nil {
					doneChan <- err
					break
				}
				_, ferr := testFile.Write(data)
				if ferr != nil {
					doneChan <- err
					break
				}
				if err == io.EOF {
					testFile.Close()
					break
				}
			*/
			//writeChan <- buf[:n]

			//print received data
			//log.Println(n, "bytes read from", src)

			//fmt.Println("Written ", fn)
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("cancelled")
		err = ctx.Err()
	case err = <-doneChan:
		fmt.Println("Done ", err, " ", testFile.Name())
		testFile.Close()
	}

	//wg.Wait()
	fmt.Println("totalpacket ", totalPackets, " totalsize ", totalSize)
	fmt.Println("total time ", time.Now().Sub(now))
}

func processDataPacket(databuf []byte, pn int, totalSize int64) int64 {
	packetNumberBytes := databuf[1:3]
	packetNumber := binary.LittleEndian.Uint16(packetNumberBytes)
	name := *filename

	if packetNumber%100 == 0 && false {
		lost := checkLostPackets(packets[name], bw)
		if lost > 0 {
			fmt.Println("Lost packet during transfer ", lost)
		}
	}

	totalSize += int64(pn) - 3

	packets[name].mu.Lock()
	if packetNumber == 3421 {
		fmt.Println(hex.EncodeToString(databuf[:100]))
	}

	if _, ok := packets[name]; ok {
		if packets[name].Lowest > packetNumber {
			packets[name].Lowest = packetNumber
		}
		if packets[name].Highest < packetNumber {
			packets[name].Highest = packetNumber
		}
		packets[name].All[packetNumber] = []byte(string(databuf[3:pn]))
		packets[name].ActualLenght += pn - 3

	}
	packets[name].mu.Unlock()

	return totalSize
}

func checkLostPackets(pPacket *packetDetails, bw *bufio.Writer) int {

	//fmt.Println("Packet check ", pPacket.Name, " L ", pPacket.ContentLength, " A ", pPacket.ActualLenght)
	start := pPacket.Lowest
	lost := 0
	name := *filename

	if start != 0 {

		ap := make([]byte, 2)
		packets[name].mu.Lock()
		for i := start; i < pPacket.Highest; i++ {
			if _, ok := pPacket.All[i]; ok {
				//fmt.Println("duplicate packet number ", packetNumber)
			} else {
				if lost == 0 {
					bw.WriteByte(0x33)
				}
				lost++
				binary.LittleEndian.PutUint16(ap, uint16(i))
				bw.Write(ap)
			}
		}
		packets[name].mu.Unlock()
	} else {
		fmt.Print("Only got packet header ")
		//Get entire packet segment on unicast repair
		return 0
	}
	if lost > 0 {
		bw.Flush()
		fmt.Println("Lost ", lost, " ", pPacket.Name)
	}
	return lost
}

type packetDetails struct {
	Lowest        uint16
	Highest       uint16
	ContentLength int
	ActualLenght  int
	All           map[uint16][]byte
	Done          bool
	Name          string
	mu            sync.Mutex
}

var packets map[string]*packetDetails

func saveFile(name string) {
	p := packets[name]
	time.Sleep(time.Millisecond * 200)
	testFile, err := os.Create(name)
	if err != nil {
		fmt.Println("Error creating file", err)
	}
	total := 0
	pack := 0
	fmt.Println("Save file ", name, " low ", p.Lowest, " high ", p.Highest)
	for i := p.Lowest; i <= p.Highest; i++ {
		d := p.All[i]
		n, err := testFile.Write(d)
		if err != nil {
			panic(err)
		}
		total += n
		pack++
	}
	testFile.Close()
	p.Done = true
	fmt.Println("Done saving ", name, " total ", total, " CL ", p.ContentLength, " p ", pack, " missing ", p.ContentLength-total)
}

func ensureDir(dirName string) error {
	err := os.Mkdir(dirName, 0755)

	if err == nil || os.IsExist(err) {
		return nil
	} else {
		return err
	}
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
