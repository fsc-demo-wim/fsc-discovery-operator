package gnmic

import (
	"context"
	"crypto/tls"
	"time"

	fscv1 "github.com/fsc-demo-wim/fsc-discovery-operator/api/v1"
	"github.com/fsc-demo-wim/fsc-discovery-operator/pkg/discoverer"
	"github.com/go-logr/logr"
	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var (
	log = logf.Log.WithName("discoverer").WithName("gnmic")
)

const (
	defaultEncoding = "JSON_IETF"
	defaultTimeout  = 30 * time.Second
	maxMsgSize      = 512 * 1024 * 1024
)

// Discoverer implements the discoverer.Discoverer interface
// and uses gnmic to manage the host.
type gnmicDiscoverer struct {
	// the node to be managed by this discoverer
	node fscv1.NetworkNode
	// a shorter path to the discoverer status data structure
	status *fscv1.DiscoveryStatus
	// access parameters for the Node
	target *fscv1.TargetDetails
	// client
	client gnmi.GNMIClient
	// credentials to log in to the BMC
	log logr.Logger
	// an event discoverer for recording significant events
	discoverer discoverer.EventPublisher
}

// LogStartup produces useful logging information on startup
func LogStartup(nn fscv1.NetworkNode) {
	log.Info("gnmic settings",
		"Protocol", nn.Spec.Target.Protocol,
		"Proxy", nn.Spec.Target.Proxy,
		"Address", nn.Spec.Target.Address,
		"Credentials", nn.Spec.Target.CredentialsName,
		"TLSInfo", nn.Spec.Target.TLSCredentialsName,
		"Insecure", nn.Spec.Target.Insecure,
		"SkipVerify", nn.Spec.Target.SkipVerify,
		"Encoding", nn.Spec.Target.Encoding,
	)
}

// New returns a new Discoverer using the Network Node configuration
func New(nn fscv1.NetworkNode, publisher discoverer.EventPublisher) (discoverer.Discoverer, error) {

	return newDiscovererWithGnmic(nn, publisher)
}

func newDiscovererWithGnmic(nn fscv1.NetworkNode, discoverer discoverer.EventPublisher) (*gnmicDiscoverer, error) {
	p := &gnmicDiscoverer{
		node:       nn,
		status:     &(nn.Status.DiscoveryStatus),
		target:     &nn.Spec.Target,
		log:        log.WithValues("node", nn.Name),
		discoverer: discoverer,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := createCollectorDialOpts()
	if err := p.CreateGNMIClient(ctx, opts...); err != nil {
		return nil, err
	}
	return p, nil
}

func createCollectorDialOpts() []grpc.DialOption {
	opts := []grpc.DialOption{}
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	opts = append(opts, grpc.WithNoProxy())
	return opts
}

func (d *gnmicDiscoverer) CreateGNMIClient(ctx context.Context, opts ...grpc.DialOption) error {
	if opts == nil {
		opts = []grpc.DialOption{}
	}
	if d.target.Insecure {
		opts = append(opts, grpc.WithInsecure())
	} else {
		tlsConfig, err := d.newTLS()
		if err != nil {
			return err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	conn, err := grpc.DialContext(timeoutCtx, d.target.Address, opts...)
	if err != nil {
		return err
	}
	d.client = gnmi.NewGNMIClient(conn)
	return nil
}

// newTLS sets up a new TLS profile
func (d *gnmicDiscoverer) newTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Renegotiation:      tls.RenegotiateNever,
		InsecureSkipVerify: d.target.SkipVerify,
	}
	err := loadCerts(tlsConfig, d.target)
	if err != nil {
		return nil, err
	}
	return tlsConfig, nil
}

func loadCerts(tlscfg *tls.Config, c *fscv1.TargetDetails) error {
	/*
		if *c.TLSCert != "" && *c.TLSKey != "" {
			certificate, err := tls.LoadX509KeyPair(*c.TLSCert, *c.TLSKey)
			if err != nil {
				return err
			}
			tlscfg.Certificates = []tls.Certificate{certificate}
			tlscfg.BuildNameToCertificate()
		}
		if c.TLSCA != nil && *c.TLSCA != "" {
			certPool := x509.NewCertPool()
			caFile, err := ioutil.ReadFile(*c.TLSCA)
			if err != nil {
				return err
			}
			if ok := certPool.AppendCertsFromPEM(caFile); !ok {
				return errors.New("failed to append certificate")
			}
			tlscfg.RootCAs = certPool
		}
	*/
	return nil
}

// Discover registers the network node with the discovery system
// and tests the connection information for the network node to verify
// that the credentials work.
func (d *gnmicDiscoverer) Discover(credentialsChanged, force bool) (result discoverer.Result, discID string, err error) {
	d.log.Info("validating management access network node")

	return result, discID, err
}

// Delete removes the network node from the discovery system.
func (d *gnmicDiscoverer) Delete() (result discoverer.Result, err error) {
	d.log.Info("Delete network node")

	return result, err
}

// IsReady checks if the provisioning backend is available
func (d *gnmicDiscoverer) IsReady() (result bool, err error) {
	d.log.Info("verifying discoverer dependencies")

	return result, err
}
