FROM golang:1.21-alpine as build

ARG BUILDTIME=no-buildtime
ARG VERSION=local-dev
ARG REVISION=no-revision

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go build -o /semgrep-network-broker -ldflags="-X 'github.com/semgrep/semgrep-network-broker/build.BuildTime=${BUILDTIME}' -X 'github.com/semgrep/semgrep-network-broker/build.Version=${VERSION}' -X 'github.com/semgrep/semgrep-network-broker/build.Revision=${REVISION}'"

FROM alpine:3.19.1

RUN adduser -D semgrep
USER semgrep
WORKDIR /home/semgrep

COPY --from=build /semgrep-network-broker /usr/bin/semgrep-network-broker

ENTRYPOINT ["/usr/bin/semgrep-network-broker"]
