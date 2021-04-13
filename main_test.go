package main

import (
	"able/admin"
	"able/config"
	"able/receiver"
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "able/protos/echo"
)

func testRunServers(t *testing.T) ([]int, string) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "able")
	if err != nil {
		t.Fatalf("Could not create tmp dir, %s", err)
	}

	listenPorts, err := freeport.GetFreePorts(6)
	if err != nil {
		t.Fatalf("Could not obtain 5 free tcp ports, %s", err)
	}

	configFile := tmpDir + "/test_config.yml"
	f, err := os.Create(configFile)
	if err != nil {
		t.Fatalf("Could not create %s %s", configFile, err)
	}
	defer f.Close()
	_, err = f.WriteString("---\n")

	certFile := tmpDir + "/server.crt"
	keyFile := tmpDir + "/server.key"

	if err := genCert(certFile, keyFile); err != nil {
		t.Fatalf("%s", err)
	}

	_ = os.Setenv("ABLE_TLS_CERT_FILE", certFile)
	_ = os.Setenv("ABLE_TLS_KEY_FILE", keyFile)
	_ = os.Setenv("ABLE_LOG_DIR", tmpDir)
	_ = os.Setenv("ABLE_LOG_OUT", "false")
	_ = os.Setenv("ABLE_ADMIN_PORT", strconv.Itoa(listenPorts[0]))
	_ = os.Setenv("ABLE_RECEIVER_HTTP_PORT", strconv.Itoa(listenPorts[1]))
	_ = os.Setenv("ABLE_RECEIVER_HTTPS_PORT", strconv.Itoa(listenPorts[2]))
	_ = os.Setenv("ABLE_RECEIVER_TCP_PORT", strconv.Itoa(listenPorts[3]))
	_ = os.Setenv("ABLE_RECEIVER_TCPS_PORT", strconv.Itoa(listenPorts[4]))
	_ = os.Setenv("ABLE_RECEIVER_GRPC_PORT", strconv.Itoa(listenPorts[5]))

	cfg, err := config.NewConfig(configFile)
	if err != nil {
		t.Errorf("Could not initialize config, %s\n", err)
	}

	promReg := prometheus.NewRegistry()

	ableAdmin := admin.NewAdmin(cfg, promReg)
	ableAdmin.Run()

	ableReceiver := receiver.NewReceiver(cfg, promReg)
	ableReceiver.Run()

	time.Sleep(time.Duration(250) * time.Millisecond)

	return listenPorts, tmpDir
}

func testReceiverHTTP(t *testing.T, transport string, port int) {
	want := "jenny8675309"

	url := fmt.Sprintf("%s://localhost:%d/echo/%s", transport, port, want)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(10) * time.Second,
	}

	req, _ := http.NewRequest("GET", url, nil)
	resp, err := httpClient.Do(req)

	if err != nil {
		t.Error(err)
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Errorf("Could not GET, %s", http.StatusText(resp.StatusCode))
		return
	}

	got, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	if string(got) != want {
		t.Errorf("Wanted %s, Got %s", want, string(got))
	}
}

func testReceiverTCP(t *testing.T, transport string, port int) {
	want := "jenny8675309"

	dialer := net.Dialer{Timeout: (time.Duration(5) * time.Second)}

	var err error
	var conn net.Conn

	addr := "localhost:" + strconv.Itoa(port)

	switch transport {
	case "tcp":
		conn, err = dialer.Dial("tcp", addr)
	case "tcps":
		conf := &tls.Config{InsecureSkipVerify: true}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, conf)
	}

	if err != nil {
		t.Errorf("Could not dial %s", addr)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(5) * time.Second))

	_, err = conn.Write([]byte(want + "\n"))
	if err != nil {
		t.Errorf("Could not tcp write %s", addr)
		return
	}

	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return
		}
		t.Errorf("Could not tcp read, %s", err)

		return
	}

	if want != strings.TrimRight(string(got), "\n") {
		t.Errorf("failed tcp read, got %s, wanted %s", got, want)
	}
}

func testReceiverGRPC(t *testing.T, port int) {
	want := "jenny8675309"

	addr := "localhost:" + strconv.Itoa(port)

	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(conf)))
	if err != nil {
		t.Errorf("Could not GRPC Dial: %s", err)
	}

	grpcClient := pb.NewEchoClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)
	defer cancel()

	r, err := grpcClient.DoEcho(ctx, &pb.EchoRequest{Request: want})
	if err != nil {
		t.Errorf("Could not Send %s", err)
		return
	}
	if r.GetReply() != want {
		t.Errorf("Wanted %s, Got %s", want, r.GetReply())
		return
	}
}

func TestListeners(t *testing.T) {
	listenPorts, tmpDir := testRunServers(t)
	defer os.RemoveAll(tmpDir)

	// testReceiverAdmin(t, "http", listenPorts[0])
	testReceiverHTTP(t, "http", listenPorts[1])
	testReceiverHTTP(t, "https", listenPorts[2])
	testReceiverTCP(t, "tcp", listenPorts[3])
	testReceiverTCP(t, "tcps", listenPorts[4])
	testReceiverGRPC(t, listenPorts[5])
}

func genCert(certFile, keyFile string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Able Bodied, LLC"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return fmt.Errorf("Failed to encode certificate to PEM")
	}
	if err := os.WriteFile(certFile, pemCert, 0644); err != nil {
		return fmt.Errorf("Could not write file %s, %s", certFile, err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("Unable to marshal private key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return fmt.Errorf("Failed to encode key to PEM")
	}

	if err := os.WriteFile(keyFile, pemKey, 0600); err != nil {
		return fmt.Errorf("Could not write file %s, %s", keyFile, err)
	}
	return nil
}
