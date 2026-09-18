package pkg

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/dealancer/validate.v2"
)

func TestEmptyConfigs(t *testing.T) {
	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Error(err)
	}

	validate.Validate(config)
}

func TestBase64StringParse(t *testing.T) {
	type TestStruct struct {
		Foo Base64String
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: base64StringDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	testValueBase64String := "KJR4EeL83nexOFihmdYciri7Mo7ciAq/b5/S0lREcns="
	testValueBytes, err := base64.StdEncoding.DecodeString(testValueBase64String)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Foo": testValueBase64String,
	}

	decoder.Decode(input)

	if reflect.DeepEqual(testValueBytes, output.Foo) {
		t.Error("No match")
	}
}

func TestSensitiveBase64StringParse(t *testing.T) {
	type TestStruct struct {
		Foo SensitiveBase64String
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: base64StringDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	testValueBase64String := "KJR4EeL83nexOFihmdYciri7Mo7ciAq/b5/S0lREcns="
	testValueBytes, err := base64.StdEncoding.DecodeString(testValueBase64String)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Foo": testValueBase64String,
	}

	decoder.Decode(input)

	if reflect.DeepEqual(testValueBytes, output.Foo) {
		t.Error("No match")
	}

	if output.Foo.String() != RedactedString {
		t.Error("String value should have been redacted")
	}
}

func TestBitSetStringParse(t *testing.T) {
	bsGet := ParseHttpMethods([]string{"GET"})

	if bsGet.Test(MethodGet) != true {
		t.Fail()
	}
	if bsGet.Test(MethodPost) != false {
		t.Fail()
	}
	if bsGet.Test(MethodDelete) != false {
		t.Fail()
	}

	bsGetPost := ParseHttpMethods([]string{"GET", "POST"})
	if bsGetPost.Test(MethodGet) != true {
		t.Fail()
	}
	if bsGetPost.Test(MethodPost) != true {
		t.Fail()
	}
	if bsGetPost.Test(MethodDelete) != false {
		t.Fail()
	}
}

func TestHttpMethodsDecodeHook(t *testing.T) {
	type TestStruct struct {
		Methods HttpMethods
	}
	output := new(TestStruct)

	dc := &mapstructure.DecoderConfig{Result: output, DecodeHook: httpMethodsDecodeHook}

	decoder, err := mapstructure.NewDecoder(dc)
	if err != nil {
		t.Error(err)
	}

	input := map[string]interface{}{
		"Methods": []string{"GET", "POST"},
	}

	decoder.Decode(input)

	expected := BitSet(0)
	expected.Set(MethodGet)
	expected.Set(MethodPost)

	if output.Methods != HttpMethods(expected) {
		t.Error(fmt.Errorf("No match: %+v != %+v", output.Methods, expected))
	}
}

const testPrivateKeyBase64 = "KJR4EeL83nexOFihmdYciri7Mo7ciAq/b5/S0lREcns="

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode test value: %v", err)
	}
	return b
}

// viper holds merged config files in global state, so it is reset on cleanup.
func writeTestConfig(t *testing.T, privateKeyBase64 string) string {
	t.Helper()
	t.Cleanup(viper.Reset)
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := fmt.Sprintf(`inbound:
  wireguard:
    privateKey: %s
    disablePeerSettingsDnsLookup: true
`, privateKeyBase64)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return path
}

func TestPrivateKeyEnvironmentVariable(t *testing.T) {
	t.Setenv(PrivateKeyEnvVar, testPrivateKeyBase64)

	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("Private key not loaded correctly from environment variable")
	}
}

func TestPrivateKeyEnvironmentVariableOverridesConfigFile(t *testing.T) {
	configFileKey := base64.StdEncoding.EncodeToString(make([]byte, WireguardPrivateKeySize))
	configPath := writeTestConfig(t, configFileKey)
	t.Setenv(PrivateKeyEnvVar, testPrivateKeyBase64)

	config, err := LoadConfig([]string{configPath}, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("Environment variable should take precedence over config file private key")
	}
}

func TestPrivateKeyConfigFileUsedWhenEnvironmentVariableUnset(t *testing.T) {
	configPath := writeTestConfig(t, testPrivateKeyBase64)
	t.Setenv(PrivateKeyEnvVar, "")

	config, err := LoadConfig([]string{configPath}, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("Private key not loaded correctly from config file")
	}
}

func TestPrivateKeyEnvironmentVariableInvalidBase64(t *testing.T) {
	t.Setenv(PrivateKeyEnvVar, "not base64!")

	_, err := LoadConfig(nil, 0)
	if err == nil {
		t.Fatal("expected an error for invalid base64 private key")
	}
	if !strings.Contains(err.Error(), "failed to decode private key from "+PrivateKeyEnvVar+" environment variable") {
		t.Errorf("unexpected error: %v", err)
	}
}

func writeTestPrivateKeyFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "privateKey")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write test private key file: %v", err)
	}
	return path
}

func TestPrivateKeyPathEnvironmentVariable(t *testing.T) {
	// genkey output and mounted secrets usually end in a newline
	path := writeTestPrivateKeyFile(t, testPrivateKeyBase64+"\n")
	t.Setenv(PrivateKeyEnvVar, "")
	t.Setenv(PrivateKeyPathEnvVar, path)

	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("Private key not loaded correctly from file named by %s", PrivateKeyPathEnvVar)
	}
}

func TestPrivateKeyEnvironmentVariableTakesPrecedenceOverPath(t *testing.T) {
	path := writeTestPrivateKeyFile(t, base64.StdEncoding.EncodeToString(make([]byte, WireguardPrivateKeySize)))
	t.Setenv(PrivateKeyEnvVar, testPrivateKeyBase64)
	t.Setenv(PrivateKeyPathEnvVar, path)

	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("%s should take precedence over %s", PrivateKeyEnvVar, PrivateKeyPathEnvVar)
	}
}

func TestPrivateKeyPathMissingFile(t *testing.T) {
	t.Setenv(PrivateKeyEnvVar, "")
	t.Setenv(PrivateKeyPathEnvVar, filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := LoadConfig(nil, 0)
	if err == nil {
		t.Fatal("expected an error when the private key file does not exist")
	}
	if !strings.Contains(err.Error(), "failed to read private key file") || !strings.Contains(err.Error(), PrivateKeyPathEnvVar) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrivateKeyPathEmptyFile(t *testing.T) {
	path := writeTestPrivateKeyFile(t, "\n")
	t.Setenv(PrivateKeyEnvVar, "")
	t.Setenv(PrivateKeyPathEnvVar, path)

	_, err := LoadConfig(nil, 0)
	if err == nil {
		t.Fatal("expected an error when the private key file is empty")
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrivateKeyWrongLengthFromPath(t *testing.T) {
	path := writeTestPrivateKeyFile(t, base64.StdEncoding.EncodeToString(make([]byte, 16)))
	t.Setenv(PrivateKeyEnvVar, "")
	t.Setenv(PrivateKeyPathEnvVar, path)

	_, err := LoadConfig(nil, 0)
	if err == nil {
		t.Fatal("expected an error for a 16 byte private key")
	}
	want := fmt.Sprintf("invalid WireGuard private key from file %q (%s): expected 32 bytes (44 base64 characters), got 16 bytes", path, PrivateKeyPathEnvVar)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("unexpected error:\n got: %v\nwant: %v", err, want)
	}
}

func TestPrivateKeyWrongLengthFromEnvironmentVariable(t *testing.T) {
	t.Setenv(PrivateKeyEnvVar, base64.StdEncoding.EncodeToString(make([]byte, 16)))

	_, err := LoadConfig(nil, 0)
	if err == nil {
		t.Fatal("expected an error for a 16 byte private key")
	}
	want := "invalid WireGuard private key from " + PrivateKeyEnvVar + " environment variable: expected 32 bytes (44 base64 characters), got 16 bytes"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("unexpected error:\n got: %v\nwant: %v", err, want)
	}
}

func TestPrivateKeyWrongLengthFromConfigFile(t *testing.T) {
	configPath := writeTestConfig(t, base64.StdEncoding.EncodeToString(make([]byte, 31)))
	t.Setenv(PrivateKeyEnvVar, "")

	_, err := LoadConfig([]string{configPath}, 0)
	if err == nil {
		t.Fatal("expected an error for a 31 byte private key")
	}
	want := "invalid WireGuard private key from config file: expected 32 bytes (44 base64 characters), got 31 bytes"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("unexpected error:\n got: %v\nwant: %v", err, want)
	}
}

func TestPrivateKeyLegacyConcatenatedKeysAccepted(t *testing.T) {
	// legacy concatenated keys (see GenerateConfig) must still load
	t.Setenv(PrivateKeyEnvVar, base64.StdEncoding.EncodeToString(make([]byte, 2*WireguardPrivateKeySize)))

	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Fatalf("legacy concatenated key should load: %v", err)
	}
	if len(config.Inbound.Wireguard.PrivateKey) != 2*WireguardPrivateKeySize {
		t.Errorf("expected %d byte key, got %d", 2*WireguardPrivateKeySize, len(config.Inbound.Wireguard.PrivateKey))
	}
}
