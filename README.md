# semgrep-network-broker

`semgrep-network-broker` is a tool for facilitating network access between the Semgrep SaaS product and customer resources that don't have connectivity to the public internet (e.g. on-prem GitHub Enterprise or GitLab Self Managed instances).

The broker supports both inbound (r2c --> customer) and outbound (customer --> r2c) traffic.

## Inbound traffic (r2c --> customer)

A Wireguard VPN tunnel is established between the broker and the Semgrep backend.

Once the tunnel is established, the broker starts a reverse proxy listening on the wireguard interface. An allowlist controls what HTTP requests are allowed to continue on.

### Configuration

Default configuration values:
```yaml
inbound:
  enabled: false      # enable the inbound proxy by setting this to true
  metrics: true       # serve prometheus metrics on the wireguard interface

  # wireguard section is provided by r2c
  wireguard:
    localAddress: ""  # local address of wireguard interface
    dns: []           # wireguard interface dns servers
    mtu: 1490         # mtu of wireguard interface
    privateKey: ""    # wireguard private key (you can generate or r2c can securely provide one)
    peers: []         # list of wireguard peers

  # allowlist section is configured by the customer
  allowlist: []       # HTTP request allowlist -- no match == reject
```

## Outbound traffic (customer --> r2c)

The Semgrep CLI communicates with semgrep.dev to load rules (pre-scan) and report findings (post-scan). This can be problematic for CI environments that block access to the public internet.

To remedy this, the Broker can also be used as a reverse proxy between the CI environment and the Semgrep backend API.

### Configuration

Default configuration values:
```yaml
outbound:
  enabled: true                 # disable the outbound proxy by setting this to false
  baseUrl: https://semgrep.dev  # override this if you're running on a separate tenant
  listen: :8080                 # socket the outbound proxy will listen on
  appToken: ""                  # adds the semgrep app token header to every proxied request
```

## Example configuration

R2c will provide the `wireguard` section for you, and can help you construct an allowlist to enforce least privilege.

```yaml
outbound:
  appToken: ...snip...
inbound:
  enabled: true
  wireguard:
    localAddress: 192.168.0.5
    privateKey: ...snip...
    peers:
    - publicKey: ...snip...
      endpoint: ...snip...
      allowedIps: 192.168.0.1/32
      persistentKeepaliveInterval: 20
  allowlist:
  - url: "https://github.example.com/*"
    allowedMethods:
    - GET
  - url: "https://github.example.com/api/v3/pulls/:org/:repo/"
    allowedMethods:
    - POST
```
