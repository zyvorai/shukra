package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/version"
)

// Webhook POSTs each detection as JSON. With a secret it signs the request:
//
//	X-Shukra-Timestamp: <unix seconds>
//	X-Shukra-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
//
// The timestamp is inside the signed bytes, so a receiver can reject an old
// request as well as a forged one.
type Webhook struct {
	url     string
	secret  []byte
	client  *http.Client
	backoff time.Duration
	tries   int
	now     func() time.Time
}

// NewWebhook validates the URL. Only http and https are accepted. Redirects are
// not followed: a 3xx counts as a failure instead of sending a signed body
// somewhere the operator did not name.
func NewWebhook(rawURL, secret string) (*Webhook, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("webhook url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("webhook url %q must be http:// or https:// with a host", rawURL)
	}
	return &Webhook{
		url:     rawURL,
		secret:  []byte(secret),
		backoff: 500 * time.Millisecond,
		tries:   3,
		now:     time.Now,
		client: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (w *Webhook) Name() string { return "webhook" }
func (w *Webhook) Close() error { return nil }

// Sign is the signature header value for a body sent at ts.
func Sign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10)))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Send retries a network error, a 429 and a 5xx, up to three attempts with a
// doubling pause. Any other status is final, since sending it again cannot help.
func (w *Webhook) Send(ctx context.Context, e event.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var last error
	for i := 0; i < w.tries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(w.backoff << (i - 1)):
			}
		}
		retry, err := w.post(ctx, body)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			return err
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", w.tries, last)
}

func (w *Webhook) post(ctx context.Context, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.Product+"/"+version.Version)
	if len(w.secret) > 0 {
		ts := w.now().Unix()
		req.Header.Set("X-Shukra-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Shukra-Signature", Sign(w.secret, ts, body))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		// url.Error repeats the URL, which often carries a token. Keep the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}
}
