FROM golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build

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

ARG BUILDTIME
# ca-certificates-bundle>=20261020-r0 distrusts emSign ECC Root CA - G3 (eMudhra intermediate key compromise, Oct 2026)
RUN apk upgrade --no-cache && apk add --no-cache 'ca-certificates-bundle>=20261020-r0' && adduser -D semgrep
USER semgrep
WORKDIR /home/semgrep

COPY --from=build /semgrep-network-broker /usr/bin/semgrep-network-broker

ENTRYPOINT ["/usr/bin/semgrep-network-broker"]
