package pkg

import (
	"testing"
)

func TestCollectSCMTargets_NoSCMs(t *testing.T) {
	config := &Config{}
	targets := CollectSCMTargets(config)
	if len(targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(targets))
	}
}

func TestCollectSCMTargets_AllSCMs(t *testing.T) {
	config := &Config{
		Inbound: InboundProxyConfig{
			GitHub:      &GitHub{BaseURL: "https://github.example.com/api/v3"},
			GitLab:      &GitLab{BaseURL: "https://gitlab.example.com/api/v4"},
			BitBucket:   &BitBucket{BaseURL: "https://bitbucket.example.com"},
			AzureDevOps: &AzureDevOps{BaseURL: "https://dev.azure.com/org"},
		},
	}
	targets := CollectSCMTargets(config)
	if len(targets) != 4 {
		t.Errorf("expected 4 targets, got %d", len(targets))
	}

	expected := []struct {
		name    string
		baseURL string
	}{
		{"GitHub", "https://github.example.com/api/v3"},
		{"GitLab", "https://gitlab.example.com/api/v4"},
		{"BitBucket", "https://bitbucket.example.com"},
		{"AzureDevOps", "https://dev.azure.com/org"},
	}

	for i, e := range expected {
		if targets[i].Name != e.name {
			t.Errorf("target[%d] name: got %q, want %q", i, targets[i].Name, e.name)
		}
		if targets[i].BaseURL != e.baseURL {
			t.Errorf("target[%d] baseURL: got %q, want %q", i, targets[i].BaseURL, e.baseURL)
		}
	}
}

func TestCollectSCMTargets_EmptyBaseURL(t *testing.T) {
	config := &Config{
		Inbound: InboundProxyConfig{
			GitHub: &GitHub{BaseURL: ""},
			GitLab: &GitLab{BaseURL: "https://gitlab.example.com/api/v4"},
		},
	}
	targets := CollectSCMTargets(config)
	if len(targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Name != "GitLab" {
		t.Errorf("expected GitLab, got %s", targets[0].Name)
	}
}

func TestCollectSCMTargets_PartialSCMs(t *testing.T) {
	config := &Config{
		Inbound: InboundProxyConfig{
			GitHub: &GitHub{BaseURL: "https://github.example.com/api/v3"},
		},
	}
	targets := CollectSCMTargets(config)
	if len(targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(targets))
	}
}

func TestAllPassed_AllPass(t *testing.T) {
	results := []TestResult{
		{Name: "a", Reachable: true},
		{Name: "b", Reachable: true},
	}
	if !AllPassed(results) {
		t.Error("expected AllPassed to return true")
	}
}

func TestAllPassed_OneFail(t *testing.T) {
	results := []TestResult{
		{Name: "a", Reachable: true},
		{Name: "b", Reachable: false, Error: "timeout"},
	}
	if AllPassed(results) {
		t.Error("expected AllPassed to return false")
	}
}

func TestAllPassed_Empty(t *testing.T) {
	if !AllPassed(nil) {
		t.Error("expected AllPassed to return true for empty results")
	}
}
