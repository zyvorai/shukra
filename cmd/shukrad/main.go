package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/shukra/internal/agent"
	"github.com/zyvorai/shukra/internal/api"
	"github.com/zyvorai/shukra/internal/observe"
	"github.com/zyvorai/shukra/internal/persist"
	"github.com/zyvorai/shukra/internal/sink"
	"github.com/zyvorai/shukra/internal/state"
	"github.com/zyvorai/shukra/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:30970", "API listen address")
	proc := flag.String("proc", "/proc", "procfs root")
	watch := flag.String("watchlist", "", "detection rules YAML: destinations, ports, exec_allow, thresholds, suppress")
	web := flag.String("web", "web/dist", "console build to serve, if present")
	dataDir := flag.String("data-dir", "", "directory that keeps detections, isolations and a recorder snapshot across restarts")
	webhookURL := flag.String("webhook-url", "", "POST each detection as JSON to this URL (secret: SHUKRA_WEBHOOK_SECRET)")
	syslogOn := flag.Bool("syslog", false, "write each detection to the local syslog daemon")
	alertFile := flag.String("alert-file", "", "append each detection as a JSON line to this file")
	tlsCert := flag.String("tls-cert", "", "serve HTTPS with this certificate (PEM). Needs -tls-key. SIGHUP reloads it")
	tlsKey := flag.String("tls-key", "", "private key for -tls-cert (PEM)")
	isolateAllow := flag.String("isolate-allow", "", "comma-separated CIDRs an isolated VM can still reach (your management and monitoring networks). Without it isolate is refused")
	noAuth := flag.Bool("no-auth", false, "serve the API without a bearer key")
	showVersion := flag.Bool("version", false, "print the version and exit")
	detachAll := flag.Bool("detach-all", false, "remove every pinned tap program and its isolation, then exit. Works while the daemon is stopped")
	flag.Parse()
	if *detachAll {
		n := observe.DetachAllTaps()
		fmt.Printf("detached %d tap links; every isolated VM is open again\n", n)
		if *dataDir != "" {
			r, err := persist.RecordReleaseAll(*dataDir, "shukrad -detach-all")
			if err != nil {
				log.Fatalf("recording the release in %s: %v", *dataDir, err)
			}
			fmt.Printf("recorded a release for %d VMs, so a restart will not isolate them again\n", r)
		} else {
			fmt.Println("no -data-dir given: the daemon's record of these isolations is unchanged, and a restart will re-apply them. Pass -data-dir to record the release")
		}
		return
	}
	if *showVersion {
		fmt.Printf("%s %s\n", version.Product, version.Version)
		return
	}

	key := os.Getenv("SHUKRA_API_KEY")
	if key == "" && !*noAuth {
		key = "shukra"
		log.Printf("WARNING: SHUKRA_API_KEY unset; using the well-known dev token %q. Set SHUKRA_API_KEY before exposing %s.", key, *listen)
	}
	if *noAuth {
		log.Printf("WARNING: -no-auth: the API on %s is open to anyone who can reach it", *listen)
	}
	readOnlyKey := os.Getenv("SHUKRA_READONLY_KEY")
	if readOnlyKey != "" && readOnlyKey == key {
		log.Fatal("SHUKRA_READONLY_KEY must differ from SHUKRA_API_KEY, or the read-only key would be an admin key")
	}
	var certs *api.CertStore
	if *tlsCert != "" || *tlsKey != "" {
		var err error
		if certs, err = api.NewCertStore(*tlsCert, *tlsKey); err != nil {
			log.Fatalf("tls: %v", err)
		}
	} else if !isLoopback(*listen) {
		log.Printf("WARNING: serving plain HTTP on %s: the bearer key crosses the network in the clear. Use -tls-cert and -tls-key, or listen on 127.0.0.1", *listen)
	}
	host, _ := os.Hostname()
	st := state.New(host)
	var store *persist.Handle
	if *dataDir != "" {
		var err error
		if store, err = persist.Attach(st, *dataDir); err != nil {
			log.Fatalf("data-dir %s: %v", *dataDir, err)
		}
	}
	var sinks []sink.Sink
	if *webhookURL != "" {
		wh, err := sink.NewWebhook(*webhookURL, os.Getenv("SHUKRA_WEBHOOK_SECRET"))
		if err != nil {
			log.Fatal(err)
		}
		if os.Getenv("SHUKRA_WEBHOOK_SECRET") == "" {
			log.Printf("WARNING: SHUKRA_WEBHOOK_SECRET is unset; webhook requests are not signed")
		}
		sinks = append(sinks, wh)
	}
	if *syslogOn {
		sl, err := sink.NewSyslog()
		if err != nil {
			log.Fatalf("syslog: %v", err)
		}
		sinks = append(sinks, sl)
	}
	if *alertFile != "" {
		f, err := sink.NewFile(*alertFile)
		if err != nil {
			log.Fatalf("alert-file: %v", err)
		}
		sinks = append(sinks, f)
	}
	var alerts *sink.Dispatcher
	if len(sinks) > 0 {
		alerts = sink.NewDispatcher(sinks...)
		st.OnDetection(alerts.Emit)
		st.SetSinkStats(alerts.Stats)
	}
	allow, err := parseAllow(*isolateAllow)
	if err != nil {
		log.Fatalf("isolate-allow: %v", err)
	}
	st.SetEnforcer(observe.NewEnforcer(allow))
	st.SetTapSource(func() []state.TapStat {
		var out []state.TapStat
		for _, t := range observe.TapSample() {
			out = append(out, state.TapStat{
				Name: t.Name, FromPkts: t.FromPkts, FromBytes: t.FromBytes, ToPkts: t.ToPkts, ToBytes: t.ToBytes,
				DroppedPkts: t.DroppedPkts, DroppedBytes: t.DroppedBytes, Isolated: t.Isolated,
			})
		}
		return out
	})
	ag, err := agent.New(st, *proc, *watch, host)
	if err != nil {
		log.Fatal(err)
	}
	var sinkNames []string
	for _, k := range sinks {
		sinkNames = append(sinkNames, k.Name())
	}
	var allowNames []string
	for _, p := range allow {
		allowNames = append(allowNames, p.String())
	}
	st.SetConfig(state.ConfigInfo{
		Listen: *listen, TLS: certs != nil, NoAuth: *noAuth, DevKey: !*noAuth && key == "shukra", KeyLen: len(key),
		ReadOnlyKey: readOnlyKey != "", DataDir: *dataDir, Sinks: sinkNames, IsolateAllow: allowNames, RulesFile: *watch,
	})
	ag.Refresh()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if certs != nil {
				if err := certs.Reload(); err != nil {
					log.Printf("tls certificate reload failed, keeping the current one: %v", err)
				} else {
					log.Printf("tls certificate reloaded")
				}
			}
			if *watch == "" {
				if certs == nil {
					log.Printf("SIGHUP ignored: no -watchlist detection file is configured")
				}
				continue
			}
			if err := ag.Reload(); err != nil {
				log.Printf("detection file reload failed, keeping the previous rules: %v", err)
				continue
			}
			log.Printf("detection rules reloaded from %s", *watch)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ag.Refresh()
			}
		}
	}()

	if store != nil {
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := store.Snapshot(); err != nil {
						log.Printf("persist: recorder snapshot failed: %v", err)
					}
				}
			}
		}()
	}

	var apiHandler http.Handler
	if *noAuth {
		apiHandler = api.NewNoAuth(st)
	} else {
		apiHandler = api.NewWithKeys(st, api.Keys{Admin: key, ReadOnly: readOnlyKey})
	}
	mux := http.NewServeMux()
	for _, p := range []string{"/api/", "/healthz", "/readyz", "/metrics"} {
		mux.Handle(p, apiHandler)
	}
	if st, err := os.Stat(*web); err == nil && st.IsDir() {
		mux.Handle("/", spa(*web))
	}

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	scheme := "http"
	if certs != nil {
		srv.TLSConfig = certs.Config()
		scheme = "https"
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	log.Printf("%s %s listening on %s://%s (%s)", version.Product, version.Version, scheme, *listen, version.Tagline)
	var serveErr error
	if certs != nil {
		serveErr = srv.ListenAndServeTLS("", "") // the certificate comes from TLSConfig
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatal(serveErr)
	}
	observe.ShutdownTaps()
	if alerts != nil {
		alerts.Close(5 * time.Second)
	}
	if store != nil {
		if err := store.Close(); err != nil {
			log.Printf("persist: closing %s: %v", *dataDir, err)
		}
	}
}

// parseAllow reads the management allow list. A bare address is a single host.
func parseAllow(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", f)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// isLoopback reports whether addr only accepts connections from this host.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func spa(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if rel != "" {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			if !strings.HasPrefix(p, filepath.Clean(dir)+string(os.PathSeparator)) && p != filepath.Clean(dir) {
				http.NotFound(w, r)
				return
			}
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}
