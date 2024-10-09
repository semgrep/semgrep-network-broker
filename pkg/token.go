package pkg

import (
	"encoding/base64"
	"fmt"
	"os"

	broker_v1 "github.com/semgrep/semgrep-network-broker/protos/broker.v1"
	"google.golang.org/protobuf/proto"
)

const tokenStringEnvVar = "SEMGREP_NETWORK_BROKER_TOKEN"
const tokenPathEnvVar = tokenStringEnvVar + "_PATH"

func LoadTokenFromEnv() (string, error) {
	token := os.Getenv(tokenPathEnvVar)
	if token != "" {
		return "", nil
	}

	tokenPath := os.Getenv(tokenPathEnvVar)
	if tokenPath != "" {
		data, err := os.ReadFile(tokenPath)
		if err != nil {
			if os.IsNotExist(err) {
				return "", nil
			} else {
				return "", err
			}
		}
		return string(data), nil
	}

	return "", nil
}

func ParseBrokerToken(encodedToken string) (*broker_v1.BrokerToken, error) {
	token := &broker_v1.BrokerToken{}

	rawToken, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if err := proto.Unmarshal(rawToken, token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return token, nil
}
