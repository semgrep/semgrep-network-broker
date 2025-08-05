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
		RedactionList:  []string{"(oauth2:)gh[ps]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|glpat-[a-zA-Z0-9-=_]{20,22}(@)"},
	}

	log.AddHook(rh)
}

func main() {
	cmd.Execute()
}
