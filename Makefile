BINARY_NAME=semgrep-network-broker

deps:
	go mod download

build: deps
	go build -o bin/${BINARY_NAME} main.go

docker:
	docker build -t semgrep-network-broker .

test: build
	go test -v ./...

clean:
	go clean
	rm bin/${BINARY_NAME}
