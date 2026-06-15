package pkg

import (
	"net/http"
	"testing"
)

func TestRedactSensitiveHeaders(t *testing.T) {
	original := http.Header{
		"Authorization":       {"Bearer ghp_secret"},
		"Proxy-Authorization": {"Basic abc123"},
		"Private-Token":       {"glpat-secret"},
		"authorization":       {"Bearer lowercase_secret"},
		"Accept":              {"application/json"},
		"X-Request-Id":        {"req-123"},
	}

	redacted := RedactSensitiveHeaders(original)

	for _, name := range []string{"Authorization", "Proxy-Authorization", "Private-Token", "authorization"} {
		if got := redacted[name]; len(got) != 1 || got[0] != RedactedString {
			t.Errorf("header %q = %v, want [%s]", name, got, RedactedString)
		}
	}

	passthrough := map[string]string{"Accept": "application/json", "X-Request-Id": "req-123"}
	for name, want := range passthrough {
		if got := redacted[name]; len(got) != 1 || got[0] != want {
			t.Errorf("header %q = %v, want [%s]", name, got, want)
		}
	}

	if got := original["Authorization"]; len(got) != 1 || got[0] != "Bearer ghp_secret" {
		t.Errorf("original header map was mutated: Authorization = %v", got)
	}
}
