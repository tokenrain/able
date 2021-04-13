package sender

import (
	"able/common"
	"able/config"
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "able/protos/echo"
)

var (
	senderRequestsError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "able_sender_requests_error",
			Help: "Number of requests that are errors",
		},
		[]string{"transport"},
	)
	senderRequestsLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "able_sender_requests_latency",
			Help:    "Duration of requests in ms.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256},
		},
		[]string{"transport"},
	)
)

// Sender is the canonical type for the sender service.
type Sender struct {
	config  *config.Config
	promReg *prometheus.Registry
}

type coordinator struct {
	addr         string
	transport    string
	latency      int
	latencyCh    chan int
	workers      []*worker
	numWorkersCh chan int
	log          *logrus.Logger
}

type worker struct {
	latency    *int
	httpClient *http.Client
	tcpClient  net.Conn
	grpcConn   *grpc.ClientConn
	grpcClient pb.EchoClient
	stopCh     chan struct{}
	log        *logrus.Logger
}

func promLatency(transport string, duration int64) {
	senderRequestsLatency.WithLabelValues(transport).Observe(float64(duration))
}

func promError(transport string, duration int64) {
	senderRequestsError.WithLabelValues(transport).Inc()
	promLatency(transport, duration)
}

// Genric Factory that returns a worker that can make any kind of
// request: http, https, tcp, tcps, grpc
func (coord *coordinator) newWorker() (*worker, error) {
	var err error

	var httpClient *http.Client
	var tcpClient net.Conn
	var grpcConn *grpc.ClientConn
	var grpcClient pb.EchoClient

	// For TCP(S)
	dialer := net.Dialer{Timeout: (time.Duration(5) * time.Second)}

	switch coord.transport {
	case "http", "https":
		httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 48,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Duration(10) * time.Second,
		}
	case "tcp":
		tcpClient, err = dialer.Dial("tcp", coord.addr)
	case "tcps":
		conf := &tls.Config{InsecureSkipVerify: true}
		tcpClient, err = tls.DialWithDialer(&dialer, "tcp", coord.addr, conf)
	case "grpc":
		conf := &tls.Config{InsecureSkipVerify: true}
		conn, err := grpc.Dial(coord.addr, grpc.WithTransportCredentials(credentials.NewTLS(conf)))
		if err == nil {
			grpcClient = pb.NewEchoClient(conn)
		}
	}

	return &worker{
		latency:    &coord.latency,
		httpClient: httpClient,
		tcpClient:  tcpClient,
		grpcConn:   grpcConn,
		grpcClient: grpcClient,
		stopCh:     make(chan struct{}, 1),
		log:        coord.log,
	}, err
}

// This is how the worker converses http(s)
func (wkr *worker) runHTTP(addr string, transport string) {
	var logFields logrus.Fields

	switch transport {
	case "http":
		logFields = logrus.Fields{
			"class": "Sender HTTP",
		}
	case "https":
		logFields = logrus.Fields{
			"class": "Sender HTTPS",
		}
	}

	for {
		select {
		case <-wkr.stopCh:
			return
		default:
			start := time.Now()
			f := common.RandomString()
			url := fmt.Sprintf("%s/echo/%s", addr, f)
			req, _ := http.NewRequest("GET", url, nil)
			resp, err := wkr.httpClient.Do(req)

			if err != nil {
				wkr.log.WithFields(logFields).Errorf("Could not GET %s, %s", url, err)
				promError(transport, time.Since(start).Milliseconds())
				continue
			}

			got, err := ioutil.ReadAll(resp.Body)
			defer resp.Body.Close()

			if err != nil {
				wkr.log.WithFields(logFields).Errorf("Could not GET %s, %s", url, err)
				promError(transport, time.Since(start).Milliseconds())
				continue
			}

			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				wkr.log.WithFields(logFields).Errorf("Could not GET %s, %s", url, http.StatusText(resp.StatusCode))
				promError(transport, time.Since(start).Milliseconds())
				continue
			}

			if f != strings.TrimRight(string(got), "\n") {
				wkr.log.WithFields(logFields).Errorf("Could not GET %s, response error", url)
				promError(transport, time.Since(start).Milliseconds())
				continue
			}

			promLatency(transport, time.Since(start).Milliseconds())
			time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
		}
	}
}

// This is how the worker converses tcp(s)
func (wkr *worker) runTCP(addr string, transport string) {
	conn := wkr.tcpClient
	defer conn.Close()

	var logFields logrus.Fields

	switch transport {
	case "tcp":
		logFields = logrus.Fields{
			"class": "Sender TCP",
		}
	case "tcps":
		logFields = logrus.Fields{
			"class": "Sender TCPS",
		}
	}

	for {
		select {
		case <-wkr.stopCh:
			return
		default:
			start := time.Now()
			f := common.RandomString()
			conn.SetDeadline(time.Now().Add(time.Duration(5) * time.Second))

			_, err := conn.Write([]byte(f + "\n"))
			if err != nil {
				wkr.log.WithFields(logFields).Errorf("Could not write %s, %s", addr, err)
				promError(transport, time.Since(start).Milliseconds())
				time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
				continue
			}

			got, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				if err == io.EOF {
					wkr.log.WithFields(logFields).Infof("Connection terminated by %s", addr)
					return
				}
				wkr.log.WithFields(logFields).Errorf("Could not TCP read %s, %s", addr, err)
				promError(transport, time.Since(start).Milliseconds())
				continue
			}
			if f != strings.TrimRight(string(got), "\n") {
				wkr.log.WithFields(logFields).Errorf("failed send of %s to %s", f, addr)
				promError(transport, time.Since(start).Milliseconds())
				continue
			}
			promLatency(transport, time.Since(start).Milliseconds())
			time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
		}
	}
}

// This is how the worker converses grpc
func (wkr *worker) runGRPC(addr string) {
	defer wkr.grpcConn.Close()

	logFields := logrus.Fields{
		"class": "Sender GRPC",
	}

	for {
		select {
		case <-wkr.stopCh:
			return
		default:
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)

			f := common.RandomString()

			r, err := wkr.grpcClient.DoEcho(ctx, &pb.EchoRequest{Request: f})
			if err != nil {
				wkr.log.WithFields(logFields).Errorf("Could not Send %s to %s", addr, err)
				promError("grpc", time.Since(start).Milliseconds())
				time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
				continue
			}
			if r.GetReply() != f {
				wkr.log.WithFields(logFields).Errorf("Could not Get %s from %s", f, addr)
				promError("grpc", time.Since(start).Milliseconds())
				time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
				continue
			}

			cancel()
			promLatency("grpc", time.Since(start).Milliseconds())
			time.Sleep(time.Duration(*wkr.latency) * time.Millisecond)
		}
	}
}

// Build the initial set of workers for a protocol. Each protocol gets a
// descrete set of workers.
func (coord *coordinator) initWorkers() error {
	anyWorkers := false

	for i := 0; i < len(coord.workers); i++ {
		wrkr, err := coord.newWorker()
		if err == nil {
			anyWorkers = true
			coord.workers[i] = wrkr
			switch coord.transport {
			case "http", "https":
				go wrkr.runHTTP(coord.addr, coord.transport)
			case "tcp", "tcps":
				go wrkr.runTCP(coord.addr, coord.transport)
			case "grpc":
				go wrkr.runGRPC(coord.addr)
			}
		}
	}

	if anyWorkers {
		return nil
	}
	return errors.New("Could not init any workers")
}

// Grow and shrink the worker pool for a protocol. This is based on
// the admin http service and the messages it passes to us.
func (coord *coordinator) adminWorkers() {
	for {
		select {
		case coord.latency = <-coord.latencyCh:
		case numWorkers := <-coord.numWorkersCh:
			if len(coord.workers) < numWorkers {
				for i := len(coord.workers) + 1; i <= numWorkers; i++ {
					wrkr, err := coord.newWorker()
					if err == nil {
						coord.workers = append(coord.workers, wrkr)
						switch coord.transport {
						case "http", "https":
							go wrkr.runHTTP(coord.addr, coord.transport)
						case "tcp", "tcps":
							go wrkr.runTCP(coord.addr, coord.transport)
						case "grpc":
							go wrkr.runGRPC(coord.addr)
						}
					}
				}
			}
			if len(coord.workers) > numWorkers {
				for i := len(coord.workers) - 1; i >= numWorkers; i-- {
					coord.workers[i].stopCh <- struct{}{}
				}
				coord.workers = coord.workers[:numWorkers-1]
			}
		}
	}
}

// For a single protocol, build a coordinator, init your workers, and
// launch and admin routine so you can grown and shrink your worker
// pool.
func (send *Sender) init(log *logrus.Logger, transport string) {
	cfg := send.config

	var coord *coordinator
	var logFields logrus.Fields

	switch transport {
	case "http":
		coord = &coordinator{
			addr:         fmt.Sprintf("%s://%s:%d", transport, cfg.Sender.Host, cfg.Sender.HTTP.Port),
			transport:    transport,
			latency:      cfg.Sender.HTTP.Latency,
			latencyCh:    cfg.Sender.HTTP.Comm.Latency,
			workers:      make([]*worker, cfg.Sender.HTTP.SendRate),
			numWorkersCh: cfg.Sender.HTTP.Comm.SendRate,
			log:          log,
		}
		logFields = logrus.Fields{
			"class": "Sender HTTP",
		}
	case "https":
		coord = &coordinator{
			addr:         fmt.Sprintf("%s://%s:%d", transport, cfg.Sender.Host, cfg.Sender.HTTPS.Port),
			transport:    transport,
			latency:      cfg.Sender.HTTPS.Latency,
			latencyCh:    cfg.Sender.HTTPS.Comm.Latency,
			workers:      make([]*worker, cfg.Sender.HTTPS.SendRate),
			numWorkersCh: cfg.Sender.HTTPS.Comm.SendRate,
			log:          log,
		}
		logFields = logrus.Fields{
			"class": "Sender HTTPS",
		}
	case "tcp":
		coord = &coordinator{
			addr:         fmt.Sprintf("%s:%d", cfg.Sender.Host, cfg.Sender.TCP.Port),
			transport:    transport,
			latency:      cfg.Sender.TCP.Latency,
			latencyCh:    cfg.Sender.TCP.Comm.Latency,
			workers:      make([]*worker, cfg.Sender.TCP.SendRate),
			numWorkersCh: cfg.Sender.TCP.Comm.SendRate,
			log:          log,
		}
		logFields = logrus.Fields{
			"class": "Sender TCP",
		}
	case "tcps":
		coord = &coordinator{
			addr:         fmt.Sprintf("%s:%d", cfg.Sender.Host, cfg.Sender.TCPS.Port),
			transport:    transport,
			latency:      cfg.Sender.TCPS.Latency,
			latencyCh:    cfg.Sender.TCPS.Comm.Latency,
			workers:      make([]*worker, cfg.Sender.TCPS.SendRate),
			numWorkersCh: cfg.Sender.TCPS.Comm.SendRate,
			log:          log,
		}
		logFields = logrus.Fields{
			"class": "Sender TCPS",
		}
	case "grpc":
		coord = &coordinator{
			addr:         fmt.Sprintf("%s:%d", cfg.Sender.Host, cfg.Sender.GRPC.Port),
			transport:    transport,
			latency:      cfg.Sender.GRPC.Latency,
			latencyCh:    cfg.Sender.GRPC.Comm.Latency,
			workers:      make([]*worker, cfg.Sender.GRPC.SendRate),
			numWorkersCh: cfg.Sender.GRPC.Comm.SendRate,
			log:          log,
		}
		logFields = logrus.Fields{
			"class": "Sender GRPC",
		}
	}

	if err := coord.initWorkers(); err == nil {
		go coord.adminWorkers()
	} else {
		log.WithFields(logFields).Error(err)
	}
}

// NewSender is the factory function for all Sender instances.
func NewSender(cfg *config.Config, promReg *prometheus.Registry) *Sender {
	promReg.MustRegister(senderRequestsError)
	promReg.MustRegister(senderRequestsLatency)

	return &Sender{
		config:  cfg,
		promReg: promReg,
	}
}

// Run completes all tasks needed to bring up an Sender service based on
// a properly configured Sender type.
func (send *Sender) Run() {
	cfg := send.config

	log := common.InitLog(cfg.Log.StdOut, cfg.Log.Dir, "sender.log", cfg.Log.Type)

	// HTTP
	if cfg.Sender.HTTP.Port != 0 {
		send.init(log, "http")
	}

	// HTTPS
	if cfg.Sender.HTTPS.Port != 0 {
		send.init(log, "https")
	}

	// TCP
	if cfg.Sender.TCP.Port != 0 {
		send.init(log, "tcp")
	}

	// TCPS
	if cfg.Sender.TCPS.Port != 0 {
		send.init(log, "tcps")
	}

	// GRPC
	if cfg.Sender.GRPC.Port != 0 {
		send.init(log, "grpc")
	}
}
