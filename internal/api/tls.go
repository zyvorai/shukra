package api

import (
	"crypto/tls"
	"errors"
	"sync/atomic"
)

// CertStore serves a TLS certificate loaded from disk and reloads it on demand,
// so a renewed certificate takes effect on SIGHUP without restarting the daemon
// or dropping the flight recorder. A failed reload keeps the certificate in use.
type CertStore struct {
	certFile, keyFile string
	cur               atomic.Pointer[tls.Certificate]
}

// NewCertStore loads the pair once and fails if it cannot, so a bad path is an
// error at start rather than a daemon that answers no one.
func NewCertStore(certFile, keyFile string) (*CertStore, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("tls needs both a certificate and a key")
	}
	c := &CertStore{certFile: certFile, keyFile: keyFile}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Reload reads the pair again. On error the previous certificate stays in use.
func (c *CertStore) Reload() error {
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	c.cur.Store(&pair)
	return nil
}

// Config is a server TLS config that always presents the current certificate.
// TLS 1.2 is the floor.
func (c *CertStore) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.cur.Load(), nil
		},
	}
}
