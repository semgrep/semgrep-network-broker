FROM golang:1.19-alpine as build

ARG BUILDTIME
ARG VERSION
ARG REVISION

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY . ./

RUN go build -o /semgrep-network-broker -ldflags="-X 'github.com/returntocorp/semgrep-network-broker/build.BuildTime=$(BUILDTIME)' -X 'github.com/returntocorp/semgrep-network-broker/build.Version=$(VERSION)' -X 'github.com/returntocorp/semgrep-network-broker/build.Revision=$(REVISION)'"

FROM alpine:3.17

ARG UID=10001
ARG GID=10001
ARG USER=semgrep

RUN addgroup -g ${GID} -S ${USER} && adduser -u ${UID} -S ${USER} -G ${USER}
USER ${user}

WORKDIR /

COPY --from=build /semgrep-network-broker /semgrep-network-broker

ENTRYPOINT ["/semgrep-network-broker"]
