BINARY_NAME := semgrep-network-broker
BUILDTIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION := local-development
REVISION := $(shell git rev-parse HEAD)


deps:
	go mod download

build: deps
	go build -o bin/$(BINARY_NAME) -ldflags="-X 'github.com/returntocorp/semgrep-network-broker/build.BuildTime=$(BUILDTIME)' -X 'github.com/returntocorp/semgrep-network-broker/build.Version=$(VERSION)' -X 'github.com/returntocorp/semgrep-network-broker/build.Revision=$(REVISION)'"

docker:
	docker build --build-arg BUILDTIME=$(BUILDTIME) --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) -t semgrep-network-broker .

test: build
	go test -v ./...

clean:
	go clean
	rm bin/${BINARY_NAME}
