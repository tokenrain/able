package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"able/admin"
	"able/config"
	"able/receiver"
	"able/sender"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var defaultConfigFile = "/etc/able/config.yml"
var configFile string

// The receiver is disabled when all non admin ports are set to 0
func receiverEnabled(cfg *config.Config) bool {
	return cfg.Receiver.HTTP.Port != 0 ||
		cfg.Receiver.HTTPS.Port != 0 ||
		cfg.Receiver.TCP.Port != 0 ||
		cfg.Receiver.TCPS.Port != 0 ||
		cfg.Receiver.GRPC.Port != 0
}

// The sender is disabled when the receiver host, ports and
// consul lookups are set to empty, 0, and empty
func senderEnabled(cfg *config.Config) bool {
	return (cfg.Sender.Host != "" &&
		(cfg.Sender.HTTP.Port != 0 ||
			cfg.Sender.HTTPS.Port != 0 ||
			cfg.Sender.TCP.Port != 0 ||
			cfg.Sender.TCPS.Port != 0 ||
			cfg.Sender.GRPC.Port != 0) ||
		cfg.Sender.Consul.URL != "")
}

func main() {
	flag.StringVar(&configFile, "config", "", "path to config file")
	flag.Parse()

	var log = logrus.New()
	log.Out = os.Stdout
	log.Formatter = &logrus.TextFormatter{
		DisableColors: true,
	}
	logFields := logrus.Fields{
		"class": "Main",
	}

	if configFile == "" {
		switch cf := os.Getenv("ABLE_CONFIG"); cf {
		case "":
			configFile = defaultConfigFile
		default:
			configFile = cf
		}
	}

	cfg, err := config.NewConfig(configFile)
	if err != nil {
		log.WithFields(logFields).Fatalf("Could not initialize config, %s", err)
	}

	// Make log directory here so we only try that once
	if !cfg.Log.StdOut {
		if err := os.MkdirAll(cfg.Log.Dir, 0755); err != nil {
			log.WithFields(logFields).Fatalf("Could not create log directory %s, %s", cfg.Log.Dir, err)
		}
	}

	// Startup Lag
	if cfg.StartupLag > 0 {
		log.WithFields(logFields).Infof("Startup Lag specified, sleeping for %d", cfg.StartupLag)
		time.Sleep(time.Duration(cfg.StartupLag) * time.Second)
	}

	var ableAdmin *admin.Admin
	var ableSender *sender.Sender
	var ableReceiver *receiver.Receiver

	isReceiver := receiverEnabled(cfg)
	isSender := senderEnabled(cfg)

	promReg := prometheus.NewRegistry()
	promReg.MustRegister(prometheus.NewGoCollector())
	promReg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	// Startup the Able Admin
	if isReceiver || isSender {
		ableAdmin = admin.NewAdmin(cfg, promReg)
		ableAdmin.Run()
	} else {
		log.WithFields(logFields).Fatalln("Both Sender and Receiver are disabled, this is an error")
	}

	// Startup the Able Receiver
	if isReceiver {
		ableReceiver = receiver.NewReceiver(cfg, promReg)
		ableReceiver.Run()
	}

	// Startup the Able Sender
	if isSender {
		ableSender = sender.NewSender(cfg, promReg)
		ableSender.Run()
	}

	// Block until Ctrl-C or Kill is triggered
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	end := <-sigs

	// Shutdown Lag
	if cfg.ShutdownLag > 0 {
		log.WithFields(logFields).Infof("Shutdown Lag specified, sleeping for %d", cfg.ShutdownLag)
		time.Sleep(time.Duration(cfg.ShutdownLag) * time.Second)
	}

	log.WithFields(logFields).Infof("Shutting down, %+v", end)
}
