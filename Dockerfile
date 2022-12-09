FROM golang:1.19-alpine as build

ARG BUILDTIME
ARG VERSION
ARG REVISION

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go build -o /semgrep-network-broker -ldflags="-X 'cmd.root.buildTime=$BUILDTIME' -X 'cmd.root.version=$VERSION' -X 'cmd.root.revision=$REVISION'"

FROM alpine:3.17

WORKDIR /

COPY --from=build /semgrep-network-broker /semgrep-network-broker

ENTRYPOINT ["/semgrep-network-broker"]
