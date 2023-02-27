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
- Docker images are also published to [ghcr.io/returntocorp/semgrep-network-broker](https://github.com/returntocorp/semgrep-network-broker/pkgs/container/semgrep-network-broker)

### Keypairs

The broker requires a Wireguard keypair in order to establish a secure connection.

- `semgrep-network-broker genkey` generates a random private key in base64 and prints it to stdout
- `semgrep-network-broker pubkey` reads a base64 private key from stdin and prints the corresponding base64 public key to stdout

Your public key is safe to share. _Do not_ share your private key with anyone (including r2c).

### Configuration

r2c will help you create a configuration file tailored to your Semgrep deployment.

**Do not** alter the `wireguard` and `heartbeat` sections.

**Do not** share the value of `inbound.wireguard.privateKey`. This is your organization's private key. Reach out to r2c on Slack if you need to rotate your Wireguard keys.

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
      methods: [GET]
      setRequestHeaders:
        Authorization: "Bearer ...snip..."

```

### Real-world example

Here's an example of allowing PR comments for a GitHub Enterprise instance hosted on https://git.example.com. Replace `<GH TOKEN>` with a GitHub PAT.

```yaml
allowlist:
- url: https://git.example.com/api/v3/repos/:owner/:repo
  methods: [GET]
  setRequestHeaders:
    Authorization: "Bearer <GH TOKEN>"
- url: https://git.example.com/api/v3/repos/:owner/:repo/pulls
  methods: [GET]
  setRequestHeaders:
    Authorization: "Bearer <GH TOKEN>"
- url: https://git.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments
  methods: [POST]
  setRequestHeaders:
    Authorization: "Bearer <GH TOKEN>"
- url: https://git.example.com/api/v3/repos/:owner/:repo/issues/:number/comments
  methods: [POST]
  setRequestHeaders:
    Authorization: "Bearer <GH TOKEN>"
```

## Usage

The broker can be run in Kubernetes, as a bare Docker container, or simply as a standalone binary on a machine. Only one instance of the broker should be run at a time.

Config file(s) are passed to the app with `-c`:

```bash
semgrep-network-broker -c config.yaml
```

Multiple config files can be overlaid on top of each other by passing multiple `-c` args (ex. `semgrep-network-broker -c config1.yaml -c config2.yaml -c config3.yaml`). Note that while maps will be merged together, arrays will be _replaced_.

Requirements:
- internet access to `wireguard.semgrep.dev` on UDP port 51820
