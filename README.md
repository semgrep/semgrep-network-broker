# semgrep-network-broker

`semgrep-network-broker` is a tool for facilitating network access between the Semgrep SaaS product and customer resources that don't have connectivity to the public internet (e.g. on-prem GitHub Enterprise or GitLab Self Managed instances).

To accomplish this, the broker establishes a Wireguard VPN tunnel with the Semgrep backend and then starts at reverse proxy listening on the wireguard interface. An allowlist controls what HTTP requests are allowed be proxied on in the customer's environment.

Examples of "inbound" traffic include:

- Pull Request comments
- JIRA integration
- Webhooks

## Configuration

r2c will provide you with a configuration file.

```yaml
inbound:
  wireguard:
    localAddress: ...snip...
    privateKey: ...snip...
    peers:
      - publicKey: ...snip...
        endpoint: ...snip...
        allowedIps: ...snip...
  healthcheckUrl: ...snip...
  allowlist:
    - url: "https://github.example.com/*"
      methods: [GET]
    - url: "https://github.example.com/api/v3/pulls/:org/:repo/"
      methods: [POST]
```
