BINARY_NAME=semgrep-network-broker

deps:
	go mod download

build:
	go build -o bin/${BINARY_NAME} main.go

test:
	go test -v ./...

clean:
	go clean
	rm bin/${BINARY_NAME}
