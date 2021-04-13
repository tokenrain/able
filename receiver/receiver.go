package receiver

import (
	"able/common"
	"able/config"
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	pb "able/protos/echo"
)

var (
	receiverRequestsError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "able_receiver_requests_error",
			Help: "Number of requests that are errors",
		},
		[]string{"transport"},
	)
	receiverRequestsLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "able_receiver_requests_latency",
			Help:    "Duration of requests in ms.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128, 256},
		},
		[]string{"transport"},
	)
)

// Receiver is the canonical type for the receiver service.
type Receiver struct {
	config  *config.Config
	promReg *prometheus.Registry
	counter struct {
		http  uint32
		https uint32
		tcp   uint32
		tcps  uint32
		grpc  uint32
	}
	bads struct {
		http   []bool
		httpMu sync.Mutex
		https  []bool
		tcp    []bool
		tcps   []bool
		grpc   []bool
	}
}

// RPC is the canonical type for the GRPC part of the receiver
// service.
type RPC struct {
	pb.UnimplementedEchoServer
	pb.UnimplementedHealthServer
	Receiver *Receiver
	Logger   *logrus.Entry
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func promLatency(transport string, duration int64) {
	receiverRequestsLatency.WithLabelValues(transport).Observe(float64(duration))
}

func promError(transport string, duration int64) {
	receiverRequestsError.WithLabelValues(transport).Inc()
	promLatency(transport, duration)
}

// Errors are based on X number of bad requests out of each batch of
// 100. We generate a random list of requests that we will mark as bad
// so as not to have regular pattern.
func (recv *Receiver) generateRandoms(amount int) []bool {
	all := make([]int, 100)
	randoms := make([]bool, 100)
	var inter []int

	for i := 0; i < 100; i++ {
		all[i] = i
	}

	counter := 100
	for i := 0; i < amount; i++ {
		rn := rand.Intn(counter)
		inter = append(inter, all[rn])
		all = append(all[:rn], all[rn+1:]...)
		counter--
	}

	for _, i := range inter {
		randoms[i] = true
	}

	return randoms
}

/*
The below 5 functions work but there was a concurrency issue with the
first implementation that I could not figure out. Orginally the reset of
the counter was done as "== 100" and there was no check that the counter
was "< 100". The counter was actually getting above 100 even though it
was supposed to be reset to 0 when it hit 100. I belive I used the
correct atomic primitives but when the number of gorotines were high, a
panic happened due to trying to read outside the length of a slice. The
implementation below gets around the issue but is likely somewhat
"incorrect" It is fine for what we are using this app for but it should
not be used in production code.
*/

func (recv *Receiver) isErrorHTTP() bool {
	cfg := recv.config

	if atomic.LoadUint32(&recv.counter.http) > 99 {
		atomic.StoreUint32(&recv.counter.http, 0)
	}

	if atomic.LoadUint32(&recv.counter.http) == 0 {
		recv.bads.http = recv.generateRandoms(cfg.Receiver.HTTP.ErrorRate)
	}

	c := atomic.LoadUint32(&recv.counter.http)

	atomic.AddUint32(&recv.counter.http, 1)

	if c < 100 {
		return recv.bads.http[c]
	}

	return false
}

func (recv *Receiver) isErrorHTTPS() bool {
	cfg := recv.config

	if atomic.LoadUint32(&recv.counter.https) > 99 {
		atomic.StoreUint32(&recv.counter.https, 0)
	}

	if atomic.LoadUint32(&recv.counter.https) == 0 {
		recv.bads.https = recv.generateRandoms(cfg.Receiver.HTTPS.ErrorRate)
	}

	c := atomic.LoadUint32(&recv.counter.https)

	atomic.AddUint32(&recv.counter.https, 1)

	if c < 100 {
		return recv.bads.https[c]
	}

	return false
}

func (recv *Receiver) isErrorTCP() bool {
	cfg := recv.config

	if atomic.LoadUint32(&recv.counter.tcp) > 99 {
		atomic.StoreUint32(&recv.counter.tcp, 0)
	}

	if atomic.LoadUint32(&recv.counter.tcp) == 0 {
		recv.bads.tcp = recv.generateRandoms(cfg.Receiver.TCP.ErrorRate)
	}

	c := atomic.LoadUint32(&recv.counter.tcp)

	atomic.AddUint32(&recv.counter.tcp, 1)

	if c < 100 {
		return recv.bads.tcp[c]
	}

	return false
}

func (recv *Receiver) isErrorTCPS() bool {
	cfg := recv.config

	if atomic.LoadUint32(&recv.counter.tcps) > 99 {
		atomic.StoreUint32(&recv.counter.tcps, 0)
	}

	if atomic.LoadUint32(&recv.counter.tcps) == 0 {
		recv.bads.tcps = recv.generateRandoms(cfg.Receiver.TCPS.ErrorRate)
	}

	c := atomic.LoadUint32(&recv.counter.tcps)

	atomic.AddUint32(&recv.counter.tcps, 1)

	if c < 100 {
		return recv.bads.tcps[c]
	}

	return false
}

func (recv *Receiver) isErrorGRPC() bool {
	cfg := recv.config

	if atomic.LoadUint32(&recv.counter.grpc) > 99 {
		atomic.StoreUint32(&recv.counter.grpc, 0)
	}

	if atomic.LoadUint32(&recv.counter.grpc) == 0 {
		recv.bads.grpc = recv.generateRandoms(cfg.Receiver.GRPC.ErrorRate)
	}

	c := atomic.LoadUint32(&recv.counter.grpc)

	atomic.AddUint32(&recv.counter.grpc, 1)

	if c < 100 {
		return recv.bads.grpc[c]
	}

	return false
}

// Check is a dummy always good gRpc check for Consul. If you need a
// service check for something like Fabio/Consul integration, you can
// use the grpc type check to get a healty service to register.
func (recv *RPC) Check(ctx context.Context, in *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{Status: 1}, nil
}

// DoEcho is gRpc service that simply echos back the string it gets. Send
// random errors based on supplied error rate.
func (recv *RPC) DoEcho(ctx context.Context, in *pb.EchoRequest) (*pb.EchoReply, error) {
	start := time.Now()

	cfg := recv.Receiver.config

	p, _ := peer.FromContext(ctx)
	reply := in.GetRequest()

	if recv.Receiver.isErrorGRPC() {
		recv.Logger.Infof("Listener sending ERROR to %s", p.Addr.String())
		time.Sleep(time.Duration(cfg.Receiver.GRPC.Latency) * time.Millisecond)
		promError("grpc", time.Since(start).Milliseconds())
		return &pb.EchoReply{}, errors.New("Generated Error")
	}

	recv.Logger.Infof("Listener sending %s to %s", reply, p.Addr.String())
	time.Sleep(time.Duration(cfg.Receiver.GRPC.Latency) * time.Millisecond)
	promLatency("grpc", time.Since(start).Milliseconds())
	return &pb.EchoReply{Reply: in.GetRequest()}, nil
}

// http(s) handler that simply echos back the string it gets. Send
// random errors based on supplied error rate.
func (recv *Receiver) echo(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	cfg := recv.config

	var transport string
	if r.TLS == nil {
		transport = "http"
	} else {
		transport = "https"
	}

	if (transport == "https") && (cfg.Receiver.HTTPS.ErrorRate != 0) {
		if recv.isErrorHTTPS() {
			time.Sleep(time.Duration(cfg.Receiver.HTTPS.Latency) * time.Millisecond)
			http.Error(w, "Server Random Error", 500)
			promError(transport, time.Since(start).Milliseconds())
			return
		}
	} else if (transport == "http") && (cfg.Receiver.HTTP.ErrorRate != 0) {
		if recv.isErrorHTTP() {
			time.Sleep(time.Duration(cfg.Receiver.HTTP.Latency) * time.Millisecond)
			http.Error(w, "Server Random Error", 500)
			promError(transport, time.Since(start).Milliseconds())
			return
		}
	}

	echo := strings.TrimPrefix(r.URL.Path, "/echo/")

	if r.TLS == nil {
		time.Sleep(time.Duration(cfg.Receiver.HTTP.Latency) * time.Millisecond)
	} else {
		time.Sleep(time.Duration(cfg.Receiver.HTTPS.Latency) * time.Millisecond)
	}

	w.WriteHeader(200)
	fmt.Fprintf(w, echo)
	promLatency(transport, time.Since(start).Milliseconds())
}

// Simple http(s) server with a single GET route
func (recv *Receiver) initHTTP(log *logrus.Logger, transport string) {
	cfg := recv.config

	m := mux.NewRouter()

	m.PathPrefix("/echo/").Handler(http.HandlerFunc(recv.echo)).Methods("GET")

	var port string
	var logFields logrus.Fields

	switch transport {
	case "http":
		port = strconv.Itoa(cfg.Receiver.HTTP.Port)
		logFields = logrus.Fields{
			"class": "Receiver HTTP",
		}
	case "https":
		port = strconv.Itoa(cfg.Receiver.HTTPS.Port)
		logFields = logrus.Fields{
			"class": "Receiver HTTPS",
		}
	}

	requestLogger := log.WithFields(logFields)

	// Define server options
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handlers.LoggingHandler(requestLogger.Writer(), m),
		ReadTimeout:  cfg.Timeout.HTTP.Read,
		WriteTimeout: cfg.Timeout.HTTP.Write,
		IdleTimeout:  cfg.Timeout.HTTP.Idle,
	}

	// Run the server on a new goroutine
	go func() {
		switch transport {
		case "http":
			if err := server.ListenAndServe(); err != nil {
				if err != http.ErrServerClosed {
					log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
				}
			}
		case "https":
			if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
				if err != http.ErrServerClosed {
					log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
				}
			}
		}
	}()

	log.WithFields(logFields).Infof("Listener started on %s", server.Addr)
}

// This is the handler for each tcp(s) connection. A message is a
// newline terminated string. We simulate an error by returning only a
// newline. This will not register to the client as an error if all they
// send is a newline.
func (recv *Receiver) tcpConnHandler(conn net.Conn, log *logrus.Logger, transport string) {
	defer conn.Close()

	cfg := recv.config

	var logFields logrus.Fields

	switch transport {
	case "tcp":
		logFields = logrus.Fields{
			"class": "Receiver TCP",
		}
	case "tcps":
		logFields = logrus.Fields{
			"class": "Receiver TCPS",
		}
	}

	for {
		netData, err := bufio.NewReader(conn).ReadString('\n')
		start := time.Now()
		if err != nil {
			if err == io.EOF {
				log.WithFields(logFields).Infof("Listener EOF from %s", conn.RemoteAddr())
				return
			}
			log.WithFields(logFields).Errorf("Listener read error from %s, %s", conn.RemoteAddr(), err)
			receiverRequestsError.WithLabelValues(transport).Inc()
			continue
		}

		got := strings.TrimRight(string(netData), "\n")

		isError := false

		if transport == "tcp" && cfg.Receiver.TCP.ErrorRate != 0 {
			if recv.isErrorTCP() {
				isError = true
			}
		} else if transport == "tcps" && cfg.Receiver.TCPS.ErrorRate != 0 {
			if recv.isErrorTCPS() {
				isError = true
			}
		}

		switch transport {
		case "tcp":
			time.Sleep(time.Duration(cfg.Receiver.TCP.Latency) * time.Millisecond)
		case "tcps":
			time.Sleep(time.Duration(cfg.Receiver.TCPS.Latency) * time.Millisecond)
		}

		if isError {
			promError(transport, time.Since(start).Milliseconds())
			log.WithFields(logFields).Errorf("Listener sending %s null", conn.RemoteAddr())
			conn.Write([]byte("\n"))
		} else {
			promLatency(transport, time.Since(start).Milliseconds())
			log.WithFields(logFields).Infof("Listener sending %s %s", conn.RemoteAddr(), got)
			conn.Write([]byte(got + "\n"))
		}
	}
}

// Sets up the tcp(s) listener. Passes off each connection to the tcp(s)
// handler for message handling.
func (recv *Receiver) initTCP(log *logrus.Logger, transport string) {
	cfg := recv.config

	var listen net.Listener
	var err error

	var logFields logrus.Fields

	var port string
	switch transport {
	case "tcp":
		port = strconv.Itoa(cfg.Receiver.TCP.Port)
		logFields = logrus.Fields{
			"class": "Receiver TCP",
		}
	case "tcps":
		port = strconv.Itoa(cfg.Receiver.TCPS.Port)
		logFields = logrus.Fields{
			"class": "Receiver TCPS",
		}
	}

	if transport == "tcps" {
		cer, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.WithFields(logFields).Fatalf("Listener failed to start: Could not LoadX509KeyPair, %s", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
		listen, err = tls.Listen("tcp", ":"+port, tlsConfig)
	} else {
		listen, err = net.Listen("tcp", ":"+port)
	}

	if err != nil {
		log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
	}
	defer listen.Close()

	log.WithFields(logFields).Infof("Listener started on %s", listen.Addr())

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.WithFields(logFields).Errorf("Listener accept error from %s, %s", conn.RemoteAddr(), err)
			continue
		}

		log.WithFields(logFields).Infof("Listener accept from %s", conn.RemoteAddr())
		go recv.tcpConnHandler(conn, log, transport)
	}
}

// gRpc server setup.
func (recv *Receiver) initGRPC(log *logrus.Logger) {
	cfg := recv.config

	logFields := logrus.Fields{
		"class": "Receiver GRPC",
	}
	port := strconv.Itoa(cfg.Receiver.GRPC.Port)

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
	}

	creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.WithFields(logFields).Fatalf("Listener failed to start: Could not LoadX509KeyPair, %s", err)
	}

	requestLogger := log.WithFields(logFields)

	s := grpc.NewServer(grpc.Creds(creds))

	// The struct that we use for the RPC methods are contain a pointer
	// to the Receiver struct. The RPC methods need access to Receiver
	// config and Receiver methods.
	r := &RPC{Receiver: recv, Logger: requestLogger}

	pb.RegisterEchoServer(s, r)
	pb.RegisterHealthServer(s, r)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
		}
	}()

	log.WithFields(logFields).Infof("Listener started on %s", lis.Addr())
}

// NewReceiver is the factory function for all Receiver instances.
func NewReceiver(cfg *config.Config, promReg *prometheus.Registry) *Receiver {
	promReg.MustRegister(receiverRequestsError)
	promReg.MustRegister(receiverRequestsLatency)

	return &Receiver{
		config:  cfg,
		promReg: promReg,
	}
}

// Run completes all tasks needed to bring up an Receiver service based on
// a properly configured Receiver type.
func (recv *Receiver) Run() {
	cfg := recv.config

	log := common.InitLog(cfg.Log.StdOut, cfg.Log.Dir, "receiver.log", cfg.Log.Type)

	// HTTP
	if cfg.Receiver.HTTP.Port != 0 {
		recv.initHTTP(log, "http")
	}

	// HTTPS
	if cfg.Receiver.HTTPS.Port != 0 {
		recv.initHTTP(log, "https")
	}

	// TCP
	if cfg.Receiver.TCP.Port != 0 {
		go recv.initTCP(log, "tcp")
	}

	// TCPS
	if cfg.Receiver.TCPS.Port != 0 {
		go recv.initTCP(log, "tcps")
	}

	// GRPC
	if cfg.Receiver.GRPC.Port != 0 {
		go recv.initGRPC(log)
	}

}
