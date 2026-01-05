package main

import (
	"github.com/semgrep/semgrep-network-broker/cmd"

	log "github.com/sirupsen/logrus"
	"github.com/whuang8/redactrus"
)

func init() {
	// Create Redactrus hook that is triggered
	// for every logger level and redacts
	// github oauth tokens from logs
	// github regex source: https://gist.github.com/magnetikonline/073afe7909ffdd6f10ef06a00bc3bc88
	// gitlab regex from semgrep-rules-secrets
	rh := &redactrus.Hook{
		AcceptedLevels: log.AllLevels,
		RedactionList: []string{
			"(oauth2:)gh[ps]_[a-zA-Z0-9]{36}(@)",
			"(oauth2:)github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}(@)",
			"(oauth2:)glpat-[a-zA-Z0-9-=_]{20,22}(@)",
			"(oauth2:)glpat-[A-Za-z0-9_-]{27,300}\\.[a-z0-9]{2}\\.[a-z0-9]{2}[a-z0-9]{7}(@)",
			"(oauth2:)glpat-[A-Za-z0-9_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}(@)",
		},
	}

	log.AddHook(rh)
}

func main() {
	cmd.Execute()
}
