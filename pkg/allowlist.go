package pkg

import (
	"net/url"

	"github.com/dunglas/go-urlpattern"
	log "github.com/sirupsen/logrus"
)

func (config AllowlistItem) Matches(method string, url *url.URL) bool {
	m := LookupHttpMethod(method)
	if m == MethodUnknown || !config.Methods.Test(m) {
		return false
	}

	pattern, err := urlpattern.New(config.URL, "", nil)
	if err != nil {
		log.WithError(err).WithField("url", config.URL).Error("failed to compile url pattern")
		return false
	}

	return pattern.Test(url.String(), config.URL)
}

func (allowlist Allowlist) FindMatch(method string, url *url.URL) (*AllowlistItem, bool) {
	for i := range allowlist {
		if allowlist[i].Matches(method, url) {
			return &allowlist[i], true
		}
	}
	return nil, false
}
