package multicast

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/iafoosball/quic-go"
	"github.com/iafoosball/quic-go/http3"
	"github.com/iafoosball/quic-go/internal/protocol"
)

type Client struct {
	*http3.Client

	hostname string
}

type RoundTripper struct {
	*http3.RoundTripper

	MultiAddr string

	Ifat *net.Interface

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// QuicConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QuicConfig *quic.Config
}

// MethodGet0RTT allows a GET request to be sent using 0-RTT.
// Note that 0-RTT data doesn't provide replay protection.
const MethodGet0RTT = "GET_0RTT"

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlive:          true,
	Versions:           []protocol.VersionNumber{protocol.VersionTLS},
}

var dialAddr = quic.DialAddrEarly

func newClient(
	hostname string,
	tlsConf *tls.Config,
	opts *http3.RoundTripperOpts,
	quicConfig *quic.Config,
	dialer func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error),
) (*Client, error) {
	if quicConfig == nil {
		quicConfig = defaultQuicConfig.Clone()
	} else if len(quicConfig.Versions) == 0 {
		quicConfig = quicConfig.Clone()
		quicConfig.Versions = []quic.VersionNumber{defaultQuicConfig.Versions[0]}
	}
	if len(quicConfig.Versions) != 1 {
		return nil, errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	quicConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	quicConfig.EnableDatagrams = opts.EnableDatagram
	//logger := utils.DefaultLogger.WithPrefix("h3 client")

	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{versionToALPN(quicConfig.Versions[0])}

	http3Client, err := http3.NewClient(hostname, tlsConf, opts, quicConfig, dialer)

	return &Client{
		Client:   http3Client,
		hostname: hostname,
	}, err
}

func versionToALPN(v protocol.VersionNumber) string {
	if v == protocol.Version1 {
		return nextProtoH3
	}
	if v == protocol.VersionTLS || v == protocol.VersionDraft29 {
		return nextProtoH3Draft29
	}
	return ""
}
