package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/tm-threemavithana/agentiam/internal/controlplane"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"gopkg.in/yaml.v3"
)

var (
	httpAddr = flag.String("http", ":8080", "HTTP API listen address")
	tcpAddr  = flag.String("tcp", ":5000", "Control Plane TCP streaming listen address")
	polFile  = flag.String("file", "policies.yaml", "Path to policies YAML file")
	logLevel = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

func loadPolicies(path string) (*policy.PoliciesYAML, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &policy.PoliciesYAML{Version: "1"}, nil
		}
		return nil, err
	}

	var py policy.PoliciesYAML
	if err := yaml.Unmarshal(b, &py); err != nil {
		return nil, err
	}
	return &py, nil
}

func savePolicies(path string, py *policy.PoliciesYAML) error {
	b, err := yaml.Marshal(py)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func main() {
	flag.Parse()

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	adminToken := os.Getenv("AGENTIAM_ADMIN_TOKEN")
	if adminToken == "" {
		logger.Error("AGENTIAM_ADMIN_TOKEN environment variable is required")
		os.Exit(1)
	}

	logger.Info("Starting AgentIAM Control Plane", "http", *httpAddr, "tcp", *tcpAddr, "file", *polFile)

	cpServer := controlplane.NewServer(*tcpAddr, logger, adminToken)
	if err := cpServer.Start(); err != nil {
		logger.Error("Failed to start Control Plane TCP server", "error", err)
		os.Exit(1)
	}
	defer cpServer.Close()

	http.HandleFunc("/api/policies", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+adminToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet {
			py, err := loadPolicies(*polFile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(py)
			return
		}

		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			var py policy.PoliciesYAML
			if err := json.Unmarshal(body, &py); err != nil {
				http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
				return
			}

			// Validate at least version is present
			if py.Version == "" {
				py.Version = "1"
			}

			if err := savePolicies(*polFile, &py); err != nil {
				http.Error(w, fmt.Sprintf("Failed to save policies: %v", err), http.StatusInternalServerError)
				return
			}

			// Broadcast to all connected proxies
			// Convert back to JSON for broadcast payload
			payload, _ := json.Marshal(py)
			cpServer.BroadcastConfig(payload)

			logger.Info("Policies updated and broadcasted to proxies", "agents_count", len(py.Agents))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	logger.Info("HTTP API Server listening", "addr", *httpAddr)
	if err := http.ListenAndServe(*httpAddr, nil); err != nil {
		logger.Error("HTTP Server failed", "error", err)
		os.Exit(1)
	}
}
