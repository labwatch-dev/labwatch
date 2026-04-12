// labwatch — lightweight homelab monitoring agent
//
// Collects system metrics, Docker stats, and service health data
// and sends it to the Homelab Intelligence API.
//
// Single binary, no dependencies, outbound-only connections.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zazastation/labwatch/internal/collector"
	"github.com/zazastation/labwatch/internal/config"
	"github.com/zazastation/labwatch/internal/transport"
)

var (
	version   = "0.2.3"
	buildDate = "dev"
)

func main() {
	configPath := flag.String("config", "/etc/labwatch/config.yaml", "Path to config file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	register := flag.Bool("register", false, "Register this agent with the API")
	flag.Parse()

	if *showVersion {
		fmt.Printf("labwatch v%s (built %s)\n", version, buildDate)
		os.Exit(0)
	}

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("labwatch v%s starting (interval: %s)", version, cfg.Interval)

	// Create transport
	sender, err := transport.New(cfg, version)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Register if requested
	if *register {
		if err := sender.Register(); err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		log.Println("Agent registered successfully")
		os.Exit(0)
	}

	// Create collectors
	collectors := []collector.Collector{
		collector.NewSystem(),
	}

	// Optionally add Docker collector
	if cfg.Docker.Enabled {
		dc, err := collector.NewDocker(cfg.Docker.Socket)
		if err != nil {
			log.Printf("Warning: Docker collector unavailable: %v", err)
		} else {
			collectors = append(collectors, dc)
		}
	}

	// Optionally add GPU collector
	if cfg.GPU.Enabled {
		collectors = append(collectors, collector.NewGPU())
	}

	// Optionally add S.M.A.R.T. disk health collector (auto-disables if smartctl missing)
	if cfg.SMART.Enabled {
		collectors = append(collectors, collector.NewSMART())
	}

	// Optionally add service checker
	if len(cfg.Services) > 0 {
		collectors = append(collectors, collector.NewServiceChecker(cfg.Services))
	}

	// Main collection loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v, shutting down...", sig)
		cancel()
	}()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Collect immediately on start
	collect(ctx, collectors, sender)

	for {
		select {
		case <-ticker.C:
			collect(ctx, collectors, sender)
		case <-ctx.Done():
			log.Println("Shutdown complete")
			return
		}
	}
}

func collect(ctx context.Context, collectors []collector.Collector, sender *transport.Sender) {
	payload := transport.Payload{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Collectors: make(map[string]interface{}),
	}

	for _, c := range collectors {
		data, err := c.Collect(ctx)
		if err != nil {
			log.Printf("Collector %s error: %v", c.Name(), err)
			continue
		}
		payload.Collectors[c.Name()] = data
	}

	if err := sender.Send(ctx, payload); err != nil {
		log.Printf("Failed to send metrics: %v", err)
	}
}
