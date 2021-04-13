package config

import (
	"os"
	"time"

	"github.com/caarlos0/env/v6"
	"gopkg.in/yaml.v2"
)

//
// Log
//
var (
	defaultLogType  = "line"
	defaultLogLevel = "info"
	defaultLogDir   = "/var/log/able"
)

// Log holds global logging configuration.
type Log struct {
	Type   string `yaml:"type"  env:"ABLE_LOG_TYPE"`
	Level  string `yaml:"level" env:"ABLE_LOG_LEVEL"`
	Dir    string `yaml:"dir"   env:"ABLE_LOG_DIR"`
	StdOut bool   `yaml:"out"   env:"ABLE_LOG_STDOUT"`
}

//
// Timeout
//
var (
	defaultTimeoutHTTPServer = 30 * time.Second
	defaultTimeoutHTTPWrite  = 10 * time.Second
	defaultTimeoutHTTPRead   = 10 * time.Second
	defaultTimeoutHTTPIdle   = 10 * time.Second
	defaultTimeoutHTTPClient = 30 * time.Second
)

// Timeout holds HTTP server and client timeouts.
type Timeout struct {
	HTTP struct {
		Server time.Duration `yaml:"server" env:"ABLE_TIMEOUT_HTTP_SERVER"`
		Write  time.Duration `yaml:"write"  env:"ABLE_TIMEOUT_HTTP_WRITE"`
		Read   time.Duration `yaml:"read"   env:"ABLE_TIMEOUT_HTTP_READ"`
		Idle   time.Duration `yaml:"idle"   env:"ABLE_TIMEOUT_HTTP_IDLE"`
		Client time.Duration `yaml:"client" env:"ABLE_TIMEOUT_HTTP_CLIENT"`
	} `yaml:"http"`
}

//
// Receiver
//

// Receiver contains some but not all configuration for the Receiver type.
type Receiver struct {
	HTTP struct {
		Port      int `yaml:"port"       env:"ABLE_RECEIVER_HTTP_PORT"`
		Latency   int `yaml:"latency"    env:"ABLE_RECEIVER_HTTP_LATENCY"`
		ErrorRate int `yaml:"error_rate" env:"ABLE_RECEIVER_HTTP_ERROR_RATE"`
	} `yaml:"http"`
	HTTPS struct {
		Port      int `yaml:"port"       env:"ABLE_RECEIVER_HTTPS_PORT"`
		Latency   int `yaml:"latency"    env:"ABLE_RECEIVER_HTTPS_LATENCY"`
		ErrorRate int `yaml:"error_rate" env:"ABLE_RECEIVER_HTTPS_ERROR_RATE"`
	} `yaml:"https"`
	TCP struct {
		Port      int `yaml:"port"       env:"ABLE_RECEIVER_TCP_PORT"`
		Latency   int `yaml:"latency"    env:"ABLE_RECEIVER_TCP_LATENCY"`
		ErrorRate int `yaml:"error_rate" env:"ABLE_RECEIVER_TCP_ERROR_RATE"`
	} `yaml:"tcp"`
	TCPS struct {
		Port      int `yaml:"port"       env:"ABLE_RECEIVER_TCPS_PORT"`
		Latency   int `yaml:"latency"    env:"ABLE_RECEIVER_TCPS_LATENCY"`
		ErrorRate int `yaml:"error_rate" env:"ABLE_RECEIVER_TCPS_ERROR_RATE"`
	} `yaml:"tcps"`
	GRPC struct {
		Port      int `yaml:"port"       env:"ABLE_RECEIVER_GRPC_PORT"`
		Latency   int `yaml:"latency"    env:"ABLE_RECEIVER_GRPC_LATENCY"`
		ErrorRate int `yaml:"error_rate" env:"ABLE_RECEIVER_GRPC_ERROR_RATE"`
	} `yaml:"grpc"`
}

//
// Sender latency defaults
//

var (
	defaultSenderHTTPLatency  = 250
	defaultSenderHTTPSLatency = 250
	defaultSenderTCPLatency   = 250
	defaultSenderTCPSLatency  = 250
	defaultSenderGRPCLatency  = 250
)

//
// Sender send rate defaults
//

var (
	defaultSenderHTTPSendRate  = 1
	defaultSenderHTTPSSendRate = 1
	defaultSenderTCPSendRate   = 1
	defaultSenderTCPSSendRate  = 1
	defaultSenderGRPCSendRate  = 1
)

//
// Sender
//

// Sender contains some but not all configuration for the Sender type.
type Sender struct {
	Host   string `yaml:"host" env:"ABLE_SENDER_HOST"`
	Consul struct {
		URL     string   `yaml:"consul_url"     env:"ABLE_SENDER_CONSUL_URL"`
		Service string   `yaml:"consul_service" env:"ABLE_SENDER_CONSUL_SERVICE"`
		Tags    []string `yaml:"consul_tags"    env:"ABLE_SENDER_CONSUL_TAGS" envSeparator:","`
	} `yaml:"consul"`
	HTTP struct {
		Port     int `yaml:"port"      env:"ABLE_SENDER_HTTP_PORT"`
		Latency  int `yaml:"latency"   env:"ABLE_SENDER_HTTP_LATENCY"`
		SendRate int `yaml:"send_rate" env:"ABLE_SENDER_HTTP_SEND_RATE"`
		Comm     struct {
			Latency  chan int
			SendRate chan int
		}
	} `yaml:"http"`
	HTTPS struct {
		Port     int `yaml:"port"      env:"ABLE_SENDER_HTTPS_PORT"`
		Latency  int `yaml:"latency"   env:"ABLE_SENDER_HTTPS_LATENCY"`
		SendRate int `yaml:"send_rate" env:"ABLE_SENDER_HTTPS_SEND_RATE"`
		Comm     struct {
			Latency  chan int
			SendRate chan int
		}
	} `yaml:"https"`
	TCP struct {
		Port     int `yaml:"port"      env:"ABLE_SENDER_TCP_PORT"`
		Latency  int `yaml:"latency"   env:"ABLE_SENDER_TCP_LATENCY"`
		SendRate int `yaml:"send_rate" env:"ABLE_SENDER_TCP_SEND_RATE"`
		Comm     struct {
			Latency  chan int
			SendRate chan int
		}
	} `yaml:"tcp"`
	TCPS struct {
		Port     int `yaml:"port"      env:"ABLE_SENDER_TCPS_PORT"`
		Latency  int `yaml:"latency"   env:"ABLE_SENDER_TCPS_LATENCY"`
		SendRate int `yaml:"send_rate" env:"ABLE_SENDER_TCPS_SEND_RATE"`
		Comm     struct {
			Latency  chan int
			SendRate chan int
		}
	} `yaml:"tcps"`
	GRPC struct {
		Port     int `yaml:"port"      env:"ABLE_SENDER_GRPC_PORT"`
		Latency  int `yaml:"latency"   env:"ABLE_SENDER_GRPC_LATENCY"`
		SendRate int `yaml:"send_rate" env:"ABLE_SENDER_GRPC_SEND_RATE"`
		Comm     struct {
			Latency  chan int
			SendRate chan int
		}
	} `yaml:"grpc"`
}

//
// Config
//

// Config contains all configuration needed for both receivers and
// senders.
type Config struct {
	ShutdownLag int      `yaml:"shutdown_lag"  env:"ABLE_SHUTDOWN_LAG"`
	StartupLag  int      `yaml:"startup_lag"   env:"ABLE_STARTUP_LAG"`
	TLSCertFile string   `yaml:"tls_cert_file" env:"ABLE_TLS_CERT_FILE"`
	TLSKeyFile  string   `yaml:"tls_key_file"  env:"ABLE_TLS_KEY_FILE"`
	AdminPort   int      `yaml:"admin_port"    env:"ABLE_ADMIN_PORT"`
	InfluxDB    []string `yaml:"influxdb"      env:"ABLE_INFLUXDB" envSeparator:","`
	Prometheus  bool     `yaml:"promethus"     env:"ABLE_PROMETHEUS"`
	DeadFile    string   `yaml:"dead_file"     env:"ABLE_DEAD_FILE"`
	SickFile    string   `yaml:"sick_file"     env:"ABLE_SICK_FILE"`
	Log         Log      `yaml:"log"`
	Timeout     Timeout  `yaml:"timeout"`
	Receiver    Receiver `yaml:"receiver"`
	Sender      Sender   `yaml:"sender"`
}

// NewConfig is the factory function for all Config instances.
func NewConfig(configFile string) (*Config, error) {
	config := &Config{}

	config.Sender.HTTP.Comm.Latency = make(chan int, 1)
	config.Sender.HTTP.Comm.SendRate = make(chan int, 1)
	config.Sender.HTTPS.Comm.Latency = make(chan int, 1)
	config.Sender.HTTPS.Comm.SendRate = make(chan int, 1)
	config.Sender.TCP.Comm.Latency = make(chan int, 1)
	config.Sender.TCP.Comm.SendRate = make(chan int, 1)
	config.Sender.TCPS.Comm.Latency = make(chan int, 1)
	config.Sender.TCPS.Comm.SendRate = make(chan int, 1)
	config.Sender.GRPC.Comm.Latency = make(chan int, 1)
	config.Sender.GRPC.Comm.SendRate = make(chan int, 1)

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// YAML into struct
	d := yaml.NewDecoder(file)
	if err := d.Decode(config); err != nil {
		return nil, err
	}

	// Environment vars into struct
	if err := env.Parse(config); err != nil {
		return nil, err
	}

	// Log defaults into struct
	if config.Log.Type == "" {
		config.Log.Type = defaultLogType
	}

	if config.Log.Level == "" {
		config.Log.Level = defaultLogLevel
	}

	if config.Log.Dir == "" {
		config.Log.Dir = defaultLogDir
	}

	// Timeout defaults into struct
	if config.Timeout.HTTP.Server == 0 {
		config.Timeout.HTTP.Server = defaultTimeoutHTTPServer
	}

	if config.Timeout.HTTP.Write == 0 {
		config.Timeout.HTTP.Write = defaultTimeoutHTTPWrite
	}

	if config.Timeout.HTTP.Read == 0 {
		config.Timeout.HTTP.Read = defaultTimeoutHTTPRead
	}

	if config.Timeout.HTTP.Idle == 0 {
		config.Timeout.HTTP.Idle = defaultTimeoutHTTPIdle
	}

	if config.Timeout.HTTP.Client == 0 {
		config.Timeout.HTTP.Client = defaultTimeoutHTTPClient
	}

	// Sender latency into struct
	if config.Sender.HTTP.Latency == 0 {
		config.Sender.HTTP.Latency = defaultSenderHTTPLatency
	}
	if config.Sender.HTTPS.Latency == 0 {
		config.Sender.HTTPS.Latency = defaultSenderHTTPSLatency
	}
	if config.Sender.TCP.Latency == 0 {
		config.Sender.TCP.Latency = defaultSenderTCPLatency
	}
	if config.Sender.TCPS.Latency == 0 {
		config.Sender.TCPS.Latency = defaultSenderTCPSLatency
	}
	if config.Sender.GRPC.Latency == 0 {
		config.Sender.GRPC.Latency = defaultSenderGRPCLatency
	}

	// Sender send rate into struct
	if config.Sender.HTTP.SendRate == 0 {
		config.Sender.HTTP.SendRate = defaultSenderHTTPSendRate
	}
	if config.Sender.HTTPS.SendRate == 0 {
		config.Sender.HTTPS.SendRate = defaultSenderHTTPSSendRate
	}
	if config.Sender.TCP.SendRate == 0 {
		config.Sender.TCP.SendRate = defaultSenderTCPSendRate
	}
	if config.Sender.TCPS.SendRate == 0 {
		config.Sender.TCPS.SendRate = defaultSenderTCPSSendRate
	}
	if config.Sender.GRPC.SendRate == 0 {
		config.Sender.GRPC.SendRate = defaultSenderGRPCSendRate
	}

	return config, nil
}
