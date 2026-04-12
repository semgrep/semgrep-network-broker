package cmd

import (
	"fmt"
	"os"

	"github.com/semgrep/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const semgrepAppTokenEnvVar = "SEMGREP_APP_TOKEN"

var setupToken string
var setupOutput string

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Automatically configure the broker with a single command",
	Long: `Generates a WireGuard keypair, registers it with the Semgrep backend,
fetches the default configuration, and writes a complete config.yaml.

Requires a Semgrep App Token (via --token or SEMGREP_APP_TOKEN env var)
and a deployment ID (--deployment-id).

Example:
  semgrep-network-broker setup --token <SEMGREP_APP_TOKEN> --deployment-id 12345
  SEMGREP_APP_TOKEN=<token> semgrep-network-broker setup -d 12345 --output /etc/broker/config.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		if jsonLog {
			log.SetFormatter(&log.JSONFormatter{FieldMap: log.FieldMap{log.FieldKeyMsg: "event"}})
		}

		token := setupToken
		if token == "" {
			token = os.Getenv(semgrepAppTokenEnvVar)
		}
		if token == "" {
			log.Panic("--token or SEMGREP_APP_TOKEN env var is required")
		}

		if deploymentId <= 0 {
			log.Panic("--deployment-id is required")
		}

		// Step 1: Generate WireGuard keypair
		fmt.Println("Generating WireGuard keypair...")
		privateKeyB64, publicKeyB64, err := pkg.GenerateKeyPair()
		if err != nil {
			log.Panic(fmt.Errorf("failed to generate keypair: %v", err))
		}
		fmt.Printf("  Public key: %s\n", publicKeyB64)

		// Step 2: Register public key with Semgrep
		fmt.Println("Registering broker with Semgrep backend...")
		instance, err := pkg.RegisterBrokerInstance(deploymentId, publicKeyB64, token)
		if err != nil {
			log.Panic(fmt.Errorf("failed to register broker instance: %v", err))
		}
		fmt.Printf("  Assigned peer IP: %s\n", instance.PeerIp)

		// Step 3: Fetch default config
		fmt.Println("Fetching default configuration...")
		defaultConfigJSON, err := pkg.FetchDefaultConfig(deploymentId)
		if err != nil {
			log.Panic(fmt.Errorf("failed to fetch default config: %v", err))
		}

		// Step 4: Build complete config YAML
		configYAML, err := pkg.BuildConfigYAML(defaultConfigJSON, privateKeyB64, instance.PeerIp)
		if err != nil {
			log.Panic(fmt.Errorf("failed to build config YAML: %v", err))
		}

		// Step 5: Write config to disk
		if err := os.WriteFile(setupOutput, configYAML, 0600); err != nil {
			log.Panic(fmt.Errorf("failed to write config file: %v", err))
		}
		fmt.Printf("Config written to: %s\n", setupOutput)
		fmt.Println()

		// Step 6: Verify connectivity using the generated config
		fmt.Println("Verifying connectivity...")
		config, err := pkg.LoadConfig([]string{setupOutput}, deploymentId)
		if err != nil {
			fmt.Printf("Warning: could not load generated config for verification: %v\n", err)
			printManualTestHint(setupOutput, deploymentId)
			return
		}

		results, err := pkg.TestConnectivity(config)
		if err != nil {
			fmt.Printf("Warning: connectivity test failed to start: %v\n", err)
			printManualTestHint(setupOutput, deploymentId)
			return
		}

		pkg.PrintTestResults(results)

		if len(results) > 0 && pkg.AllPassed(results) {
			fmt.Println("\nSetup complete. Your broker is ready to use.")
		} else {
			fmt.Println("\nSetup complete. Config file written, but some connectivity tests did not pass.")
		}

		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Printf("  1. Edit %s to add your SCM configuration (github, gitlab, etc.)\n", setupOutput)
		fmt.Printf("  2. Run: semgrep-network-broker test -c %s -d %d\n", setupOutput, deploymentId)
		fmt.Printf("  3. Start the broker: semgrep-network-broker -c %s -d %d\n", setupOutput, deploymentId)
	},
}

func printManualTestHint(configPath string, deplId int) {
	fmt.Println("The config file was written successfully. You can test manually with:")
	fmt.Printf("  semgrep-network-broker test -c %s -d %d\n", configPath, deplId)
}

func init() {
	setupCmd.Flags().StringVar(&setupToken, "token", "", "Semgrep App Token (or set SEMGREP_APP_TOKEN env var)")
	setupCmd.Flags().StringVar(&setupOutput, "output", "config.yaml", "path to write the generated config file")
	rootCmd.AddCommand(setupCmd)
}
