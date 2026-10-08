FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build

ARG BUILDTIME=no-buildtime
ARG VERSION=local-dev
ARG REVISION=no-revision

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go build -o /semgrep-network-broker -ldflags="-X 'github.com/semgrep/semgrep-network-broker/build.BuildTime=${BUILDTIME}' -X 'github.com/semgrep/semgrep-network-broker/build.Version=${VERSION}' -X 'github.com/semgrep/semgrep-network-broker/build.Revision=${REVISION}'"

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0

RUN apk upgrade --no-cache && adduser -D semgrep
USER semgrep
WORKDIR /home/semgrep

COPY --from=build /semgrep-network-broker /usr/bin/semgrep-network-broker

ENTRYPOINT ["/usr/bin/semgrep-network-broker"]
