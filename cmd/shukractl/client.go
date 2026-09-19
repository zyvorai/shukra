package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func loadConfig() {
	if os.Getenv("SHUKRA_SKIP_DOTENV") != "1" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			loadEnvFile(filepath.Join(home, ".shukra", "env"))
			if os.Getenv("SHUKRA_API_KEY") == "" {
				if b, err := os.ReadFile(filepath.Join(home, ".shukra", "api-key")); err == nil {
					if k := strings.TrimSpace(string(b)); k != "" {
						_ = os.Setenv("SHUKRA_API_KEY", k)
					}
				}
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("SHUKRA_URL")); v != "" {
		base = strings.TrimRight(v, "/")
	} else {
		base = "http://127.0.0.1:30970"
	}
	if os.Getenv("SHUKRA_TLS_INSECURE") == "" && urlIsLoopback(base) && strings.HasPrefix(base, "https://") {
		_ = os.Setenv("SHUKRA_TLS_INSECURE", "true")
	}
}

func loadEnvFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		_ = os.Setenv(k, v)
	}
}

func urlIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func httpClient() *http.Client {
	c := &http.Client{Timeout: 15 * time.Second}
	v := strings.TrimSpace(os.Getenv("SHUKRA_TLS_INSECURE"))
	insecure := strings.EqualFold(v, "true") || v == "1"
	switch {
	case insecure:
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	case os.Getenv("SHUKRA_CA_FILE") != "":
		// Trust a private CA without turning verification off.
		if pool, err := caPool(os.Getenv("SHUKRA_CA_FILE")); err == nil {
			c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
		}
	}
	return c
}

func caPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s has no PEM certificate", path)
	}
	return pool, nil
}

func do(method, path string, body []byte) ([]byte, int, error) {
	loadConfig()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	if key := os.Getenv("SHUKRA_API_KEY"); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("X-Shukra-Actor", "shukractl")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return b, resp.StatusCode, fmt.Errorf("%s %s: %s", method, path, strings.TrimSpace(string(b)))
	}
	return b, resp.StatusCode, nil
}

func decode(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

var base = "http://127.0.0.1:30970"
