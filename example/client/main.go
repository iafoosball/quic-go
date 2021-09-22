package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"github.com/iafoosball/quic-go/internal/protocol"
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
	now := time.Now()
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
	l.SetReadBuffer(protocol.InitialPacketSizeIPv4)

	testFile, err := os.Create("test.ts")
	if err != nil {
		fmt.Println("Error creating file", err)
	}
	fmt.Println(testFile)

	totalPackets := 0
	totalSize := 0

	doneChan := make(chan error, 1)
	ctx := context.Background()

	go func() {
		//size := 32 * 1024
		//buf := make([]byte, size)

		buf := make([]byte, 1439)
		for {

			n, _, err := l.ReadFromUDP(buf)
			if err != nil {
				doneChan <- err
				break
			}

			//print received data
			//log.Println(n, "bytes read from", src)

			if true {
				short := false
				for i := 0; i < 10; i++ {
					if buf[i]&0x80 == 0 {
						short = true
						//fmt.Printf(" %x ", buf[i])
					}
				}
				if !short {
					fmt.Print("Not short header")
				}
			}
			totalPackets += 1
			totalSize += n
			if totalPackets%15 == 0 {
				l.SetReadDeadline(time.Now().Add(1 * time.Second))
			}

			//b := make(buf)
			/*
				n, err := res.Body.Read(buf)
				if err != nil {
					if err == io.EOF {
						//testFile.Close()
					} else {
						log.Fatal("ReadFromBody failed:", err)
					}
				}
			*/
			_, ferr := testFile.Write(buf[0:n])
			if ferr != nil {
				doneChan <- err
				break
			}
			if err == io.EOF {
				testFile.Close()
				break
			}
			//fmt.Println("Written ", fn)
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("cancelled")
		err = ctx.Err()
	case err = <-doneChan:
		fmt.Println("Done ", err)
	}

	//wg.Wait()
	fmt.Println("totalpacket ", totalPackets, " totalsize ", totalSize)
	fmt.Println("total time ", time.Now().Sub(now))
}
