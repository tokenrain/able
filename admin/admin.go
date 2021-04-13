package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"able/common"
	"able/config"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Admin is the canonical type for the admin service.
type Admin struct {
	isHealthy bool
	resource  struct {
		memory int
		CPU    int
		comm   struct {
			memory chan int
			CPU    chan int
		}
	}
	config  *config.Config
	promReg *prometheus.Registry
}

func (a *Admin) consumeMemory() {
	var size int
	var consume []byte
	for {
		select {
		case size = <-a.resource.comm.memory:
			amount := size * 262144
			consume = nil

			for j := 0; j < amount-1; j++ {
				consume = append(consume, 'x')
			}
		}
	}
}

func (a *Admin) consumeCPU() {
	var size int
	var consume [](chan struct{})
	for {
		select {
		case size = <-a.resource.comm.CPU:
			for _, done := range consume {
				done <- struct{}{}
			}
			consume = nil

			for j := 0; j < size; j++ {
				done := make(chan struct{}, 1)
				consume = append(consume, done)
				go func() {
					for {
						select {
						case <-done:
							return
						default:
						}
					}
				}()
			}
		}
	}
}

func (a *Admin) getHealth(w http.ResponseWriter, r *http.Request) {
	if a.isHealthy {
		w.WriteHeader(200)
		fmt.Fprintf(w, "Healthy")
	} else {
		http.Error(w, "Not Healthy", 500)
	}
}

func (a *Admin) setHealth(w http.ResponseWriter, r *http.Request) {
	var mutex = &sync.Mutex{}

	h := r.URL.Query()["healthy"]

	if len(h) == 0 {
		http.Error(w, "Bad Request", 400)
		return
	}

	healthly, err := strconv.ParseBool(h[0])
	if err != nil {
		http.Error(w, fmt.Sprint("%s", err), 400)
		return
	}

	mutex.Lock()
	switch healthly {
	case true:
		a.isHealthy = true
	case false:
		a.isHealthy = false
	}
	mutex.Unlock()

	w.WriteHeader(200)
	fmt.Fprintln(w, "Ok")
}

func (a *Admin) getAdminResource(t string) (map[string]int, error) {
	resource := make(map[string]int)
	var err error

	switch t {
	case "memory":
		resource["memory"] = a.resource.memory
	case "cpu":
		resource["cpu"] = a.resource.CPU
	case "all":
		resource["memory"] = a.resource.memory
		resource["cpu"] = a.resource.CPU
	default:
		err = errors.New("Bad Request")
	}

	return resource, err
}

func (a *Admin) setAdminResource(t string, value int) error {
	var err error
	var mutex = &sync.Mutex{}

	mutex.Lock()
	switch t {
	case "memory":
		a.resource.memory = value
		a.resource.comm.memory <- value
	case "cpu":
		a.resource.CPU = value
		a.resource.comm.CPU <- value
	default:
		err = errors.New("Bad Request")
	}
	mutex.Unlock()

	return err
}

func (a *Admin) getReceiverLatency(t string) (map[string]int, error) {
	latency := make(map[string]int)
	var err error

	switch t {
	case "http":
		latency["http"] = a.config.Receiver.HTTP.Latency
	case "https":
		latency["https"] = a.config.Receiver.HTTPS.Latency
	case "tcp":
		latency["tcp"] = a.config.Receiver.TCP.Latency
	case "tcps":
		latency["tcps"] = a.config.Receiver.TCPS.Latency
	case "grpc":
		latency["grpc"] = a.config.Receiver.GRPC.Latency
	case "all":
		latency["http"] = a.config.Receiver.HTTP.Latency
		latency["https"] = a.config.Receiver.HTTPS.Latency
		latency["tcp"] = a.config.Receiver.TCP.Latency
		latency["tcps"] = a.config.Receiver.TCPS.Latency
		latency["grpc"] = a.config.Receiver.GRPC.Latency
	default:
		err = errors.New("Bad Request")
	}

	return latency, err
}

func (a *Admin) setReceiverLatency(t string, value int) error {
	var err error
	var mutex = &sync.Mutex{}

	mutex.Lock()
	switch t {
	case "http":
		a.config.Receiver.HTTP.Latency = value
	case "https":
		a.config.Receiver.HTTPS.Latency = value
	case "tcp":
		a.config.Receiver.TCP.Latency = value
	case "tcps":
		a.config.Receiver.TCPS.Latency = value
	case "grpc":
		a.config.Receiver.GRPC.Latency = value
	default:
		err = errors.New("Bad Request")
	}
	mutex.Unlock()

	return err
}

func (a *Admin) getReceiverErrorRate(t string) (map[string]int, error) {
	errRate := make(map[string]int)
	var err error

	switch t {
	case "http":
		errRate["http"] = a.config.Receiver.HTTP.ErrorRate
	case "https":
		errRate["https"] = a.config.Receiver.HTTPS.ErrorRate
	case "tcp":
		errRate["tcp"] = a.config.Receiver.TCP.ErrorRate
	case "tcps":
		errRate["tcps"] = a.config.Receiver.TCPS.ErrorRate
	case "grpc":
		errRate["grpc"] = a.config.Receiver.GRPC.ErrorRate
	case "all":
		errRate["http"] = a.config.Receiver.HTTP.ErrorRate
		errRate["https"] = a.config.Receiver.HTTPS.ErrorRate
		errRate["tcp"] = a.config.Receiver.TCP.ErrorRate
		errRate["tcps"] = a.config.Receiver.TCPS.ErrorRate
		errRate["grpc"] = a.config.Receiver.GRPC.ErrorRate
	default:
		err = errors.New("Bad Request")
	}

	return errRate, err
}

func (a *Admin) setReceiverErrorRate(t string, value int) error {
	var err error
	var mutex = &sync.Mutex{}

	mutex.Lock()
	switch t {
	case "http":
		a.config.Receiver.HTTP.ErrorRate = value
	case "https":
		a.config.Receiver.HTTPS.ErrorRate = value
	case "tcp":
		a.config.Receiver.TCP.ErrorRate = value
	case "tcps":
		a.config.Receiver.TCPS.ErrorRate = value
	case "grpc":
		a.config.Receiver.GRPC.ErrorRate = value
	default:
		err = errors.New("Bad Request")
	}
	mutex.Unlock()

	return err
}

func (a *Admin) getSenderLatency(t string) (map[string]int, error) {
	latency := make(map[string]int)
	var err error

	switch t {
	case "http":
		latency["http"] = a.config.Sender.HTTP.Latency
	case "https":
		latency["https"] = a.config.Sender.HTTPS.Latency
	case "tcp":
		latency["tcp"] = a.config.Sender.TCP.Latency
	case "tcps":
		latency["tcps"] = a.config.Sender.TCPS.Latency
	case "grpc":
		latency["grpc"] = a.config.Sender.GRPC.Latency
	case "all":
		latency["http"] = a.config.Sender.HTTP.Latency
		latency["https"] = a.config.Sender.HTTPS.Latency
		latency["tcp"] = a.config.Sender.TCP.Latency
		latency["tcps"] = a.config.Sender.TCPS.Latency
		latency["grpc"] = a.config.Sender.GRPC.Latency
	default:
		err = errors.New("Bad Request")
	}

	return latency, err
}

func (a *Admin) setSenderLatency(t string, value int) error {
	var err error
	var mutex = &sync.Mutex{}

	mutex.Lock()
	switch t {
	case "http":
		a.config.Sender.HTTP.Latency = value
		a.config.Sender.HTTP.Comm.Latency <- value
	case "https":
		a.config.Sender.HTTPS.Latency = value
		a.config.Sender.HTTPS.Comm.Latency <- value
	case "tcp":
		a.config.Sender.TCP.Latency = value
		a.config.Sender.TCP.Comm.Latency <- value
	case "tcps":
		a.config.Sender.TCPS.Latency = value
		a.config.Sender.TCPS.Comm.Latency <- value
	case "grpc":
		a.config.Sender.GRPC.Latency = value
		a.config.Sender.GRPC.Comm.Latency <- value
	default:
		err = errors.New("Bad Request")
	}
	mutex.Unlock()

	return err
}

func (a *Admin) getSenderSendRate(t string) (map[string]int, error) {
	var sendRate map[string]int
	var err error

	switch t {
	case "http":
		sendRate["http"] = a.config.Sender.HTTP.SendRate
	case "https":
		sendRate["https"] = a.config.Sender.HTTPS.SendRate
	case "tcp":
		sendRate["tcp"] = a.config.Sender.TCP.SendRate
	case "tcps":
		sendRate["tcps"] = a.config.Sender.TCPS.SendRate
	case "grpc":
		sendRate["grpc"] = a.config.Sender.GRPC.SendRate
	case "all":
		sendRate["http"] = a.config.Sender.HTTP.SendRate
		sendRate["https"] = a.config.Sender.HTTPS.SendRate
		sendRate["tcp"] = a.config.Sender.TCP.SendRate
		sendRate["tcps"] = a.config.Sender.TCPS.SendRate
		sendRate["grpc"] = a.config.Sender.GRPC.SendRate
	default:
		err = errors.New("Bad Request")
	}

	return sendRate, err
}

func (a *Admin) setSenderSendRate(t string, value int) error {
	var err error
	var mutex = &sync.Mutex{}

	mutex.Lock()
	switch t {
	case "http":
		a.config.Sender.HTTP.SendRate = value
		a.config.Sender.HTTP.Comm.SendRate <- value
	case "https":
		a.config.Sender.HTTPS.SendRate = value
		a.config.Sender.HTTPS.Comm.SendRate <- value
	case "tcp":
		a.config.Sender.TCP.SendRate = value
		a.config.Sender.TCP.Comm.SendRate <- value
	case "tcps":
		a.config.Sender.TCPS.SendRate = value
		a.config.Sender.TCPS.Comm.SendRate <- value
	case "grpc":
		a.config.Sender.GRPC.SendRate = value
		a.config.Sender.GRPC.Comm.SendRate <- value
	default:
		err = errors.New("Bad Request")
	}
	mutex.Unlock()

	return err
}

func (a *Admin) getTunable(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	var tunable map[string]int
	var err error

	var myType string
	switch vars["type"] {
	case "":
		myType = "all"
	default:
		myType = vars["type"]
	}

	switch vars["scope"] {
	case "admin":
		switch vars["tunable"] {
		case "resource":
			tunable, err = a.getAdminResource(myType)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	case "receiver":
		switch vars["tunable"] {
		case "latency":
			tunable, err = a.getReceiverLatency(myType)
		case "error":
			tunable, err = a.getReceiverErrorRate(myType)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	case "sender":
		switch vars["tunable"] {
		case "latency":
			tunable, err = a.getSenderLatency(myType)
		case "send":
			tunable, err = a.getSenderSendRate(myType)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	default:
		http.Error(w, "Bad Request", 400)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("%s", err), 400)
		return
	}

	jsonTunable, err := json.Marshal(tunable)
	if err != nil {
		http.Error(w, fmt.Sprint("%s", err), 500)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintf(w, string(jsonTunable))
	}
}

func (a *Admin) setTunable(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	if len(r.URL.Query()["value"]) == 0 {
		http.Error(w, "Bad Request", 400)
		return
	}

	value, err := strconv.Atoi(r.URL.Query()["value"][0])
	if err != nil {
		http.Error(w, fmt.Sprint("%s", err), 400)
		return
	}

	switch vars["scope"] {
	case "admin":
		switch vars["tunable"] {
		case "resource":
			err = a.setAdminResource(vars["type"], value)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	case "receiver":
		switch vars["tunable"] {
		case "latency":
			err = a.setReceiverLatency(vars["type"], value)
		case "error":
			err = a.setReceiverErrorRate(vars["type"], value)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	case "sender":
		switch vars["tunable"] {
		case "latency":
			err = a.setSenderLatency(vars["type"], value)
		case "send":
			err = a.setSenderSendRate(vars["type"], value)
		default:
			http.Error(w, "Bad Request", 400)
			return
		}
	default:
		http.Error(w, "Bad Request", 400)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprint("%s", err), 400)
	}

	w.WriteHeader(200)
	fmt.Fprintf(w, "Ok")
}

// NewAdmin is the factory function for all Admin instances.
func NewAdmin(cfg *config.Config, promReg *prometheus.Registry) *Admin {
	a := new(Admin)
	a.config = cfg
	a.promReg = promReg
	a.resource.comm.memory = make(chan int, 1)
	a.resource.comm.CPU = make(chan int, 1)

	return a
}

// Run completes all tasks needed to bring up an Admin service based on
// a properly configured Admin type.
func (a *Admin) Run() {
	cfg := a.config

	log := common.InitLog(cfg.Log.StdOut, cfg.Log.Dir, "admin.log", cfg.Log.Type)
	logFields := logrus.Fields{
		"class": "Admin HTTPS",
	}

	r := mux.NewRouter()

	r.Handle("/metrics", promhttp.HandlerFor(a.promReg, promhttp.HandlerOpts{})).Methods("GET")

	r.HandleFunc("/health", a.getHealth).Methods("GET")
	r.HandleFunc("/health", a.setHealth).Methods("PUT")

	r.HandleFunc("/{scope}/{tunable}", a.getTunable).Methods("GET")

	r.HandleFunc("/{scope}/{tunable}/{type}", a.getTunable).Methods("GET")
	r.HandleFunc("/{scope}/{tunable}/{type}", a.setTunable).Methods("PUT")

	server := &http.Server{
		Addr:         ":" + strconv.Itoa(cfg.AdminPort),
		Handler:      handlers.LoggingHandler(log.Writer(), r),
		ReadTimeout:  cfg.Timeout.HTTP.Read,
		WriteTimeout: cfg.Timeout.HTTP.Write,
		IdleTimeout:  cfg.Timeout.HTTP.Idle,
	}

	go func() {
		if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			if err != http.ErrServerClosed {
				log.WithFields(logFields).Fatalf("Listener failed to start, %v", err)
			}
		}
	}()

	log.WithFields(logFields).Infof("Listener started on %s", server.Addr)

	go a.consumeMemory()
	go a.consumeCPU()

	if cfg.DeadFile != "" {
		if _, err := os.Stat(cfg.DeadFile); err == nil {
			log.WithFields(logFields).Fatalln("I have been asked nicely to die!")
		}
	}

	if cfg.SickFile != "" {
		if _, err := os.Stat(cfg.SickFile); err == nil {
			a.isHealthy = false
			return
		}
	}

	a.isHealthy = true
}
