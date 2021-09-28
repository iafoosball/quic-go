package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"github.com/iafoosball/quic-go/internal/testdata"
	"github.com/iafoosball/quic-go/internal/utils"
	"github.com/iafoosball/quic-go/logging"
	"github.com/iafoosball/quic-go/multicast"
	"github.com/iafoosball/quic-go/qlog"
)

func main() {
	verbose := flag.Bool("v", false, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	hostString := flag.String("h", "localhost:8081", "host string")
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

	roundTripperHttp3 := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
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
	totalSize := 0

	packets = make(map[string]*packetDetails)
	doneChan := make(chan error, 1)
	ctx := context.Background()

	now := time.Now()
	pn := 0

	done := false
	started := false

	name := ""

	go func() {

		for {

			n, err := l.Read(databuf)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {

					fmt.Println("Done with ", name, " ", pn)
					start := packets[name].Lowest
					lost := 0
					for i := start; i < packets[name].Highest; i++ {
						if _, ok := packets[name].All[i]; ok {
							//fmt.Println("duplicate packet number ", packetNumber)
						} else {
							lost++
							fmt.Print(i, " ")
						}
					}
					if lost > 0 {
						fmt.Println()
					}
					fmt.Println("Lost packets ", lost)
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
			if databuf[0]&0x32 == 0 {
				started = true
				reader := bufio.NewReader(strings.NewReader(string(databuf[0:n]) + "\r\n"))
				tp := textproto.NewReader(reader)

				mimeHeader, err := tp.ReadMIMEHeader()
				if err != nil {
					log.Fatal(err)
				}

				// http.Header and textproto.MIMEHeader are both just a map[string][]string
				httpHeader := http.Header(mimeHeader)
				//log.Println(httpHeader)
				name = "video/" + httpHeader.Get("filename")
				fmt.Println(name)

				err = ensureDir(path.Dir(name))
				if err != nil {
					panic(err)
				}

				testFile, err = os.Create(name)
				if err != nil {
					fmt.Println("Error creating file", err)
				}
				contentLenght, err := strconv.ParseInt(httpHeader.Get("Content-Length"), 10, 64)
				packets[name] = &packetDetails{
					Lowest:        65535,
					Highest:       0,
					ContentLength: contentLenght,
					ActualLenght:  0,
					All:           make(map[uint16][]byte),
				}

			} else if databuf[0] == 0x30 || databuf[0]&0x30 == 0 || databuf[0]&0x31 == 0 && started {

				packetNumberBytes := databuf[1:3]
				packetNumber := binary.LittleEndian.Uint16(packetNumberBytes)

				totalPackets += 1
				fw, err := testFile.Write(databuf[3:pn])
				if err != nil {
					panic(err)
				}
				totalSize += fw
				if false {
					fmt.Println(fw)
				}
				if _, ok := packets[name]; ok {
					if packets[name].Lowest > packetNumber {
						packets[name].Lowest = packetNumber
					}
					if packets[name].Highest < packetNumber {
						packets[name].Highest = packetNumber
					}
					packets[name].All[packetNumber] = databuf[3:pn]
					packets[name].ActualLenght += fw

				}
			}
			if done {

				l.SetReadDeadline(time.Now().Add(time.Second * 30))
				testFile.Close()
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

type packetDetails struct {
	Lowest        uint16
	Highest       uint16
	ContentLength int64
	ActualLenght  int
	All           map[uint16][]byte
	File          *os.File
}

var packets map[string]*packetDetails

func saveFile(name string) {
	p := packets[name]
	fmt.Println("Save file ", name)
	for _, v := range p.All {
		p.File.Write(v)
	}
	fmt.Println("Done saving ", name)
}

func ensureDir(dirName string) error {
	err := os.Mkdir(dirName, 0755)

	if err == nil || os.IsExist(err) {
		return nil
	} else {
		return err
	}
}
