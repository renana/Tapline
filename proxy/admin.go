package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

func serveAdmin(addr string, store *Store, cfg *sync.RWMutex, conf *ProxyConfig) error {
	mux := http.NewServeMux()
	health := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"sidecar":true}`))
	}
	mux.HandleFunc("/healthz", health)
	mux.HandleFunc("/v1/health", health)
	mux.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		cfg.RLock()
		c := *conf
		cfg.RUnlock()
		writeJSON(w, 200, map[string]any{
			"sidecar": true, "logs": store.Summaries(), "stats": store.Stats(), "config": c,
		})
	})
	mux.HandleFunc("/v1/logs/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/logs/")
		if e := store.ByID(id); e != nil {
			writeJSON(w, 200, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("null"))
	})
	mux.HandleFunc("/v1/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		store.Clear()
		cfg.RLock()
		c := *conf
		cfg.RUnlock()
		writeJSON(w, 200, map[string]any{
			"sidecar": true, "logs": store.Summaries(), "stats": store.Stats(), "config": c,
		})
	})
	mux.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid_json"})
			return
		}
		cfg.Lock()
		if s, ok := v["envoy"].(string); ok && s != "" {
			conf.Envoy = s
			conf.CustomUpstream = s
		}
		if s, ok := v["mode"].(string); ok {
			conf.Mode = s
		}
		if b, ok := v["proxyProtocol"].(bool); ok {
			conf.ProxyProtocol = b
		}
		if n, ok := v["timeoutMs"].(float64); ok {
			ms := uint64(n)
			if ms < 500 {
				ms = 500
			}
			if ms > 30000 {
				ms = 30000
			}
			conf.TimeoutMs = ms
		}
		copyCfg := *conf
		cfg.Unlock()
		writeJSON(w, 200, copyCfg)
	})
	return http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
