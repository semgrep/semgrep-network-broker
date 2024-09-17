package pkg

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/dealancer/validate.v2"
)

func TestEmptyConfigs(t *testing.T) {
	config, err := LoadConfig(nil, 0, 0)
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
