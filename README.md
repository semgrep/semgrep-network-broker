# semgrep-network-broker

**NOTE:** These docs are in-progress. Feel free to direct any questions / feedback / improvements to your private channel on the Semgrep slack!

The Semgrep Network Broker facilitates secure access between Semgrep and a private network.

The broker accomplishes this by establishing a Wireguard VPN tunnel with the Semgrep backend, and then proxying inbound (r2c --> customer) HTTP requests through this tunnel. This approach allows Semgrep to interact with on-prem resources without having to expose them to the public internet.

Examples of inbound traffic include:

- Pull Request comments
- JIRA integrations
- Webhooks

## Setup

### Build

- Run `make build` to generate the `semgrep-network-broker` binary
- Run `make docker` to generate a docker image
- Docker images are also published to ghcr.io/returntocorp/semgrep-network-broker

### Configuration

r2c will provide a configuration file tailored to your Semgrep deployment.

**Do not** alter the `wireguard` and `heartbeat` sections.

**Do not** share the value of `inbound.wireguard.privateKey`. Reach out to r2c on Slack if you need to rotate your Wireguard keys.

Example:
```yaml
inbound:
  wireguard:
    localAddress: ...
    privateKey: ...
    peers:
      - publicKey: ...
        endpoint: ...
        allowedIps: ...
  heartbeat:
    url: ...
  allowlist: [...]
```

### Allowlist

The `allowlist` configuration section controls what HTTP requests are allowed to be forwarded out of the broker. The first matching allowlist item is used. No allowlist match means the request will not be proxied.

Examples:
```yaml
inbound:
  allowlist:
    # allow GET requests from http://example.com/foo (exact URL match)
    - url: http://example.com/foo
      methods: [GET]
    # allow GET or POST requests from any path on http://example.com
    - url: http://example.com/*
      methods: [GET, POST]
    # allow GET requests from a URL that looks like a GitHub Enterprise review comments URL, and add a bearer token to the request
    - url: http://example.com/api/v3/repos/:owner/:repo/pulls/:number/comments
      setRequestHeaders:
        Authorization: "Bearer ...snip..."

```

## Usage

The broker can be run in Kubernetes, as a bare Docker container, or simply as a standalone binary on a machine. Only one instance of the broker should be run at a time.

Config file(s) are passed to the app with `-c`:

```bash
semgrep-native-broker -c config.yaml
```

Requirements:
- internet access to `wireguard.TENANT.semgrep.dev` on UDP port 51820 (replace TENANT with your tenant name)
