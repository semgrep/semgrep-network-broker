package pkg

import (
	"net/url"
	"testing"
)

func urlMustParse(rawURL string) *url.URL {
	url, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}

	return url
}

func assertAllowlistMatch(t *testing.T, allowlist *Allowlist, method string, rawURL string, shouldMatch bool) {
	_, match := allowlist.FindMatch(method, urlMustParse(rawURL))
	if match != shouldMatch {
		t.Errorf("%v %v match result was %v, expected %v", method, rawURL, match, shouldMatch)
	}
}

func TestAllowlistMethodMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:            "https://foo.com/get-only",
			AllowedMethods: []string{"GET"},
		},
		AllowlistItem{
			URL:            "https://foo.com/post-only",
			AllowedMethods: []string{"POST"},
		},
		AllowlistItem{
			URL:            "https://foo.com/get-or-post",
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-only", false)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/post-only", false)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/post-only", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/post-only", false)

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "POST", "https://foo.com/get-or-post", true)
	assertAllowlistMatch(t, allowlist, "DELETE", "https://foo.com/get-or-post", false)
}

func TestAllowlistDomainMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:            "https://foo.com/*",
			AllowedMethods: []string{"GET"},
		},
		AllowlistItem{
			URL:            "https://bar.com/*",
			AllowedMethods: []string{"GET"},
		},
	}

	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/get-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://bar.com/bar-only", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://baz.com/baz", false)
}

func TestAllowlistPathMatch(t *testing.T) {
	allowlist := &Allowlist{
		AllowlistItem{
			URL:            "https://foo.com/hardcoded-path",
			AllowedMethods: []string{"GET"},
		},
		AllowlistItem{
			URL:            "https://foo.com/wildcard-path/*",
			AllowedMethods: []string{"GET"},
		},
		AllowlistItem{
			URL:            "https://foo.com/variable-path/:variable",
			AllowedMethods: []string{"GET"},
		},
	}

	// test path matching
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/wildcard-path/a/b", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/variable-path/a/b", false)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path", true)
	assertAllowlistMatch(t, allowlist, "GET", "https://foo.com/hardcoded-path/bla", false)
}
