package pkg

import (
	"net/url"
	"strings"

	"github.com/ucarion/urlpath"
)

func stringInSlice(needle string, haystack []string) bool {
	for i := range haystack {
		if strings.EqualFold(needle, haystack[i]) {
			return true
		}
	}
	return false
}

func (config AllowlistItem) Matches(method string, url *url.URL) bool {
	if !stringInSlice(method, config.AllowedMethods) {
		return false
	}

	parsedUrl, _ := url.Parse(config.URL)

	if parsedUrl.Scheme != url.Scheme || parsedUrl.Host != url.Host {
		return false
	}

	matcher := urlpath.New(parsedUrl.Path)
	if _, matches := matcher.Match(url.Path); matches {
		return true
	}

	return false
}

func (allowlist Allowlist) FindMatch(method string, url *url.URL) (*AllowlistItem, bool) {
	for i := range allowlist {
		if allowlist[i].Matches(method, url) {
			return &allowlist[i], true
		}
	}
	return nil, false
}
