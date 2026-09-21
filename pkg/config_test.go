package pkg

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-viper/mapstructure/v2"
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
	t.Cleanup(viper.Reset)
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

func TestPrivateKeyEnvironmentVariableOverridesMalformedConfigFileKey(t *testing.T) {
	// a stale placeholder left in the config file must not block the env key
	configPath := writeTestConfig(t, "REPLACE-ME-WITH-REAL-KEY")
	t.Setenv(PrivateKeyEnvVar, testPrivateKeyBase64)

	config, err := LoadConfig([]string{configPath}, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	expected := SensitiveBase64String(mustDecodeBase64(t, testPrivateKeyBase64))
	if !reflect.DeepEqual(config.Inbound.Wireguard.PrivateKey, expected) {
		t.Errorf("Environment variable should take precedence over malformed config file private key")
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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
	t.Cleanup(viper.Reset)
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

// LoadConfig merges into viper's package-level config, so each case starts and leaves a
// clean one. The peer DNS lookup is off because these cases only exercise config merging.
func loadConfigFiles(t *testing.T, bodies ...string) (*Config, error) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "config-base.yaml")}
	bodies = append([]string{"inbound:\n  wireguard:\n    disablePeerSettingsDnsLookup: true\n"}, bodies...)

	for i, body := range bodies {
		if i > 0 {
			paths = append(paths, filepath.Join(dir, fmt.Sprintf("config-%d.yaml", i)))
		}
		if err := os.WriteFile(paths[i], []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}

	return LoadConfig(paths, 0)
}

func mustLoadConfigFiles(t *testing.T, bodies ...string) *Config {
	t.Helper()

	config, err := loadConfigFiles(t, bodies...)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	return config
}

const scmsGitHubA = `inbound:
  scms:
    - type: github
      baseUrl: https://gh-a.example.com/api/v3
`

func TestSCMsAcrossFilesAccumulate(t *testing.T) {
	config := mustLoadConfigFiles(t, scmsGitHubA, `inbound:
  scms:
    - type: github
      baseUrl: https://gh-b.example.com/api/v3
`)

	if len(config.Inbound.SCMs) != 2 {
		t.Fatalf("expected 2 scms, got %v: %+v", len(config.Inbound.SCMs), config.Inbound.SCMs)
	}

	// Both instances reach allowlist generation, not just the last file's.
	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh-a.example.com/api/v3/repos/o/r", true)
	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh-b.example.com/api/v3/repos/o/r", true)
}

func TestSCMsSameBaseUrlAmend(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      token: from-first
      allowCodeAccess: true
`, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      token: from-second
`)

	if len(config.Inbound.SCMs) != 1 {
		t.Fatalf("expected 1 scm, got %v: %+v", len(config.Inbound.SCMs), config.Inbound.SCMs)
	}

	scm := config.Inbound.SCMs[0]
	if scm.Token != "from-second" {
		t.Errorf("token was %q, expected the later file to win", scm.Token)
	}
	if !scm.AllowCodeAccess {
		t.Error("allowCodeAccess was cleared by a file that did not mention it")
	}
}

func TestSCMsAllowCodeAccessClearedExplicitly(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      allowCodeAccess: true
`, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      allowCodeAccess: false
`)

	if config.Inbound.SCMs[0].AllowCodeAccess {
		t.Error("an explicit allowCodeAccess: false did not clear the flag")
	}

	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh.example.com/api/v3/repos/o/r/contents", false)
}

func TestSCMsCoexistWithProviderKey(t *testing.T) {
	config := mustLoadConfigFiles(t, scmsGitHubA, `inbound:
  github:
    baseUrl: https://gh-legacy.example.com/api/v3
`)

	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh-a.example.com/api/v3/repos/o/r", true)
	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh-legacy.example.com/api/v3/repos/o/r", true)
}

func TestSCMsRejectBadEntries(t *testing.T) {
	for name, body := range map[string]string{
		"unknown type": `inbound:
  scms:
    - type: gitbucket
      baseUrl: https://scm.example.com
`,
		"missing baseUrl": `inbound:
  scms:
    - type: github
`,
		"not a list": `inbound:
  scms:
    type: github
    baseUrl: https://scm.example.com
`,
		// A misspelled allowCodeAccess would otherwise merge in as a stray key and leave
		// the real flag as an earlier file set it.
		"unknown key": `inbound:
  scms:
    - type: github
      baseUrl: https://scm.example.com
      allowCodeAcess: false
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigFiles(t, body); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

func TestSCMsRejectProviderKeyOverlap(t *testing.T) {
	_, err := loadConfigFiles(t, `inbound:
  github:
    baseUrl: https://gh.example.com/api/v3
    allowCodeAccess: false
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      allowCodeAccess: true
`)

	// Left to merge, the two would generate separate allowlists and the permissive
	// allowCodeAccess would win.
	if err == nil {
		t.Fatal("expected the duplicate SCM to be rejected, got no error")
	}
}

func TestSCMsBaseUrlHostIsCaseInsensitive(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://GH.example.com/api/v3
      allowCodeAccess: true
`, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      allowCodeAccess: false
`)

	if len(config.Inbound.SCMs) != 1 {
		t.Fatalf("expected the host casing to be ignored, got %v entries: %+v",
			len(config.Inbound.SCMs), config.Inbound.SCMs)
	}

	if config.Inbound.SCMs[0].AllowCodeAccess {
		t.Error("allowCodeAccess survived a later file that cleared it")
	}
}

func TestSCMsBaseUrlPathIsCanonicalized(t *testing.T) {
	// Spellings that url.URL.JoinPath reduces to /api/v3, and so generate rules
	// indistinguishable from the first file's.
	for _, baseURL := range []string{
		"https://gh.example.com/api/v3/",
		"https://gh.example.com/api/v3//",
		"https://gh.example.com/api/v3/.",
		"https://gh.example.com/api/v4/../v3",
	} {
		t.Run(baseURL, func(t *testing.T) {
			config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3
      token: from-first
      allowCodeAccess: true
`, fmt.Sprintf(`inbound:
  scms:
    - type: github
      baseUrl: %s
      token: from-second
      allowCodeAccess: false
`, baseURL))

			if len(config.Inbound.SCMs) != 1 {
				t.Fatalf("expected the path spelling to be ignored, got %v entries: %+v",
					len(config.Inbound.SCMs), config.Inbound.SCMs)
			}

			if config.Inbound.SCMs[0].AllowCodeAccess {
				t.Error("allowCodeAccess survived a later file that cleared it")
			}

			assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://gh.example.com/api/v3/repos/o/r/contents", false)

			// The shadowed entry would otherwise keep injecting the superseded token.
			item, ok := config.Inbound.Allowlist.FindMatch("GET", urlMustParse("https://gh.example.com/api/v3/repos/o/r"))
			if !ok {
				t.Fatal("expected the merged scm to still generate an allowlist")
			}
			if got := item.SetRequestHeaders["Authorization"]; got != "Bearer from-second" {
				t.Errorf("Authorization was %q, expected the later file's token", got)
			}
		})
	}
}

func TestSCMsDistinctBaseUrlPathsStaySeparate(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://scm.example.com/tenant-a/api/v3
    - type: github
      baseUrl: https://scm.example.com/tenant-b/api/v3
`)

	if len(config.Inbound.SCMs) != 2 {
		t.Fatalf("expected 2 scms, got %v: %+v", len(config.Inbound.SCMs), config.Inbound.SCMs)
	}
}

func TestSCMsRejectProviderKeyOverlapAcrossPathSpellings(t *testing.T) {
	_, err := loadConfigFiles(t, `inbound:
  github:
    baseUrl: https://gh.example.com/api/v3
    allowCodeAccess: true
  scms:
    - type: github
      baseUrl: https://gh.example.com/api/v3/
      allowCodeAccess: false
`)

	if err == nil {
		t.Fatal("expected the duplicate SCM to be rejected, got no error")
	}
}

func TestSCMsRejectSharedGitHost(t *testing.T) {
	for name, body := range map[string]string{
		"github pair": `inbound:
  scms:
    - type: github
      baseUrl: https://scm.example.com/tenant-a/api/v3
      allowCodeAccess: true
    - type: github
      baseUrl: https://scm.example.com/tenant-b/api/v3
`,
		"gitlab pair": `inbound:
  scms:
    - type: gitlab
      baseUrl: https://scm.example.com/tenant-a/api/v4
    - type: gitlab
      baseUrl: https://scm.example.com/tenant-b/api/v4
      allowCodeAccess: true
`,
		"bitbucket pair": `inbound:
  scms:
    - type: bitbucket
      baseUrl: https://scm.example.com/a/rest/api/1.0
      allowCodeAccess: true
    - type: bitbucket
      baseUrl: https://scm.example.com/b/rest/api/1.0
      allowCodeAccess: true
`,
		// The clone rules collide whichever section declares the instance.
		"provider key and list entry": `inbound:
  github:
    baseUrl: https://scm.example.com/tenant-a/api/v3
    allowCodeAccess: true
  scms:
    - type: github
      baseUrl: https://scm.example.com/tenant-b/api/v3
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigFiles(t, body); err == nil {
				t.Error("expected the shared git host to be rejected, got no error")
			}
		})
	}
}

func TestSCMsAllowSharedHostWithoutCodeAccess(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: github
      baseUrl: https://scm.example.com/tenant-a/api/v3
    - type: github
      baseUrl: https://scm.example.com/tenant-b/api/v3
`)

	if len(config.Inbound.SCMs) != 2 {
		t.Fatalf("expected 2 scms, got %v: %+v", len(config.Inbound.SCMs), config.Inbound.SCMs)
	}

	assertAllowlistMatch(t, &config.Inbound.Allowlist, "POST", "https://scm.example.com/o/r/git-upload-pack", false)
	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://scm.example.com/tenant-a/api/v3/repos/o/r", true)
	assertAllowlistMatch(t, &config.Inbound.Allowlist, "GET", "https://scm.example.com/tenant-b/api/v3/repos/o/r", true)
}

func TestSCMsAllowSharedHostForAzureDevOps(t *testing.T) {
	config := mustLoadConfigFiles(t, `inbound:
  scms:
    - type: azuredevops
      baseUrl: https://ado.example.com/org-a
      token: token-a
      allowCodeAccess: true
    - type: azuredevops
      baseUrl: https://ado.example.com/org-b
      token: token-b
      allowCodeAccess: true
`)

	// Azure DevOps keeps the base URL path in its clone rules, so each org gets its own.
	for _, tc := range []struct{ url, token string }{
		{"https://ado.example.com/org-a/ns/proj/_git/repo/git-upload-pack", "Basic " + base64.StdEncoding.EncodeToString([]byte("token-a"))},
		{"https://ado.example.com/org-b/ns/proj/_git/repo/git-upload-pack", "Basic " + base64.StdEncoding.EncodeToString([]byte("token-b"))},
	} {
		item, ok := config.Inbound.Allowlist.FindMatch("POST", urlMustParse(tc.url))
		if !ok {
			t.Fatalf("%v was not allowed", tc.url)
		}
		if got := item.SetRequestHeaders["Authorization"]; got != tc.token {
			t.Errorf("%v got Authorization %q, expected %q", tc.url, got, tc.token)
		}
	}
}
