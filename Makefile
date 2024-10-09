BINARY_NAME := semgrep-network-broker
BUILDTIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION := local-development
REVISION := $(shell git rev-parse HEAD)

.PHONY: deps docker test clean protos
.DEFAULT_GOAL := test

deps:
	go mod download

protos: broker.proto
	buf generate

build: deps protos
	go build -o bin/$(BINARY_NAME) -ldflags="-X 'github.com/semgrep/semgrep-network-broker/build.BuildTime=$(BUILDTIME)' -X 'github.com/semgrep/semgrep-network-broker/build.Version=$(VERSION)' -X 'github.com/semgrep/semgrep-network-broker/build.Revision=$(REVISION)'"

docker:
	docker build --build-arg BUILDTIME=$(BUILDTIME) --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t semgrep-network-broker .

test: build
	go test -v ./...

clean:
	go clean
	rm bin/${BINARY_NAME}
