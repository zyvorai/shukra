package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/state"
)

// writePair writes a self-signed certificate with the given serial for 127.0.0.1.
func writePair(t *testing.T, dir string, serial int64) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "shukra-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

// serveTLS runs handler the way shukrad does: an http.Server whose certificate
// comes only from TLSConfig.GetCertificate, through ServeTLS with no files.
func serveTLS(t *testing.T, cs *CertStore, handler http.Handler) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, TLSConfig: cs.Config()}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestCertStoreReloadsWithoutRestartAndKeepsTheOldOneOnFailure(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	cs, err := NewCertStore(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, cs, New(state.New("n"), "k"))

	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("served %d", got)
	}
	writePair(t, dir, 2) // a renewed certificate replaces the files on disk
	if got := servedSerial(t, addr); got != 1 {
		t.Fatal("the new certificate was picked up before a reload was asked for")
	}
	if err := cs.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := servedSerial(t, addr); got != 2 {
		t.Fatalf("after reload served %d", got)
	}

	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cs.Reload(); err == nil {
		t.Fatal("a broken certificate reloaded")
	}
	if got := servedSerial(t, addr); got != 2 {
		t.Fatalf("a failed reload dropped the working certificate: served %d", got)
	}
}

func TestCertStoreRefusesToStartOnAnIncompletePair(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	for name, args := range map[string][2]string{
		"no key":       {cert, ""},
		"no cert":      {"", key},
		"missing file": {cert, filepath.Join(dir, "nope.pem")},
		"mismatched":   {cert, cert},
	} {
		if _, err := NewCertStore(args[0], args[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTLSFloorIsOneDotTwo(t *testing.T) {
	dir := t.TempDir()
	cs, err := NewCertStore(func() (string, string) { return writePair(t, dir, 1) }())
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, cs, http.NotFoundHandler())
	old := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	if conn, err := tls.Dial("tcp", addr, old); err == nil {
		conn.Close()
		t.Fatal("a TLS 1.1 client was served")
	}
}
