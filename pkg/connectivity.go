package pkg

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestResult holds the result of a single connectivity test.
type TestResult struct {
	Name       string
	URL        string
	Reachable  bool
	StatusCode int
	Latency    time.Duration
	Error      string
}

// SCMTarget describes an SCM endpoint to test.
type SCMTarget struct {
	Name    string
	BaseURL string
}

// CollectSCMTargets extracts configured SCM endpoints from the config.
func CollectSCMTargets(config *Config) []SCMTarget {
	var targets []SCMTarget
	if config.Inbound.GitHub != nil && config.Inbound.GitHub.BaseURL != "" {
		targets = append(targets, SCMTarget{Name: "GitHub", BaseURL: config.Inbound.GitHub.BaseURL})
	}
	if config.Inbound.GitLab != nil && config.Inbound.GitLab.BaseURL != "" {
		targets = append(targets, SCMTarget{Name: "GitLab", BaseURL: config.Inbound.GitLab.BaseURL})
	}
	if config.Inbound.BitBucket != nil && config.Inbound.BitBucket.BaseURL != "" {
		targets = append(targets, SCMTarget{Name: "BitBucket", BaseURL: config.Inbound.BitBucket.BaseURL})
	}
	if config.Inbound.AzureDevOps != nil && config.Inbound.AzureDevOps.BaseURL != "" {
		targets = append(targets, SCMTarget{Name: "AzureDevOps", BaseURL: config.Inbound.AzureDevOps.BaseURL})
	}
	return targets
}

// TestConnectivity brings up the WireGuard tunnel and tests connectivity
// to the heartbeat endpoint and each configured SCM.
func TestConnectivity(config *Config) ([]TestResult, error) {
	tnet, teardown, err := config.Inbound.Wireguard.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start WireGuard tunnel: %v", err)
	}
	defer teardown()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: 10 * time.Second,
	}

	var results []TestResult

	if config.Inbound.Heartbeat.URL != "" {
		results = append(results, testEndpoint(client, tnet, "Heartbeat", config.Inbound.Heartbeat.URL))
	}

	for _, target := range CollectSCMTargets(config) {
		results = append(results, testEndpoint(client, tnet, target.Name, target.BaseURL))
	}

	return results, nil
}

func testEndpoint(client *http.Client, tnet *netstack.Net, name string, targetURL string) TestResult {
	start := time.Now()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return TestResult{
			Name:  name,
			URL:   targetURL,
			Error: fmt.Sprintf("invalid URL: %v", err),
		}
	}

	resp, err := client.Do(req)
	latency := time.Since(start)

	if err != nil {
		log.WithField("target", name).WithError(err).Debug("connectivity.test.failure")
		return TestResult{
			Name:    name,
			URL:     targetURL,
			Latency: latency,
			Error:   err.Error(),
		}
	}
	defer resp.Body.Close()

	// Any HTTP response (even 401/403) proves network connectivity
	log.WithField("target", name).WithField("status", resp.StatusCode).WithField("latency", latency).Debug("connectivity.test.success")

	return TestResult{
		Name:       name,
		URL:        targetURL,
		Reachable:  true,
		StatusCode: resp.StatusCode,
		Latency:    latency,
	}
}

// PrintTestResults prints a formatted summary of test results.
func PrintTestResults(results []TestResult) {
	fmt.Println()
	fmt.Println("Connectivity Test Results")
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("  %-14s %-8s %-10s %-8s %s\n", "TARGET", "STATUS", "HTTP CODE", "LATENCY", "DETAILS")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	for _, r := range results {
		status := "FAIL"
		if r.Reachable {
			status = "PASS"
		}

		httpCode := "-"
		if r.StatusCode > 0 {
			httpCode = fmt.Sprintf("%d", r.StatusCode)
		}

		latency := "-"
		if r.Latency > 0 {
			latency = r.Latency.Round(time.Millisecond).String()
		}

		details := ""
		if r.Error != "" {
			details = r.Error
		} else if r.StatusCode == 401 || r.StatusCode == 403 {
			details = "reachable (auth required)"
		}

		fmt.Printf("  %-14s %-8s %-10s %-8s %s\n", r.Name, status, httpCode, latency, details)
	}

	fmt.Println("─────────────────────────────────────────────────────────────────")
}

// AllPassed returns true if every test result was reachable.
func AllPassed(results []TestResult) bool {
	for _, r := range results {
		if !r.Reachable {
			return false
		}
	}
	return true
}
