package main

import (
	"github.com/returntocorp/semgrep-network-broker/cmd"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	cmd.Execute()
}
