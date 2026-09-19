package pkg

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
