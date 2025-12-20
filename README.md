# semgrep-network-broker

The Semgrep Network Broker facilitates secure access between Semgrep and a private network.

The broker creates a WireGuard VPN tunnel to the Semgrep backend and proxies inbound HTTP requests (from Semgrep to the customer) through it. This allows Semgrep to communicate with private network resources like a Source Code Manager (SCM) without exposing them to the public internet.

Examples of inbound traffic include:

- Pull request (PR) or merge request (MR) comments.
- Code access for Semgrep Managed Scans (SMS) if enabled.
- Webhooks.

> **NOTE:** These docs are in-progress. Feel free to direct any questions / feedback / improvements to your private channel on the Semgrep slack!

## Feature Availability

The Semgrep Network Broker is a feature that must be enabled in your Semgrep organization (org) before setup.
It is only available to paying customers.
> Contact the [Semgrep support team](https://semgrep.dev/docs/support) to discuss having it enabled for your organization.
If you will be using the broker with a dedicated Semgrep tenant, please note that in your request.

## Deployment

The network broker can be run as a bare Docker container, in a Kubernetes cluster, or simply as a standalone binary on a machine.

Only one instance of the wireguard-based broker can be run concurrently. Multiple brokers with the same configuration can cause disconnects, instability, and package loss.

### System Requirements
- CPU: 1
- RAM: 512 MB

### Network Requirements
- Between Semgrep and Broker:
  - Allow traffic from `wireguard.semgrep.dev` on UDP port 51820. If on a dedicated Semgrep tenant, allow traffic from `wireguard.<tenant-name>.semgrep.dev` instead.
  - If using the `--deployment-id` CLI flag, allow outbound to `semgrep.dev` on TCP port 443 for HTTPS.
- Between Broker and each private network resource:
  - Enable outbound on TCP ports 80 and 443 for HTTP/HTTPS communication.

> **NOTE** To determine the IP addresses for a domain, use dig. The addresses are listed under the ANSWER section. Example: `dig wireguard.semgrep.dev`

### Artifacts
You can choose between deploying pre-made artifacts or building your own.
#### Pre-built by Semgrep
- Docker images are available from [ghcr.io/semgrep/semgrep-network-broker](https://github.com/semgrep/semgrep-network-broker/pkgs/container/semgrep-network-broker).
- A simple [Kubernetes Manifest](kubernetes.yaml) is present within the repository. This should be extended for production.

#### Build Yourself
> **NOTE:** The Semgrep Network broker uses [Buf](https://buf.build/) for protobuf compilation. If you are building the broker from scratch outside of Docker, make sure you have the Buf CLI installed: https://buf.build/docs/installation

- Binary: Run `make build` to build the `semgrep-network-broker` binary locally.
- Docker Image: Run `make docker` to build a docker image.

## Configuration

The network broker requires configuration in two locations:
1. The broker settings page in your Semgrep AppSec Platform organization.
2. A YAML file passed to the broker at execution.

The configuration examples below assume you are using a published network broker docker image.

### Pre-requisites
#### Enable the Broker Settings page in Semgrep.
Must be enabled by [Semgrep support](README.md#feature-availability).

#### Semgrep Organization ID
To retrieve your organization ID `ORGANIZATION_ID`, go to your Semgrep organization's [settings page](https://semgrep.dev/orgs/-/settings/general/identifiers). From the General settings page, select Identifiers from the sub-menu. The numerical ID is located under the heading `Organization ID`.

#### Key Generation

The broker requires a Wireguard keypair in order to establish a secure connection.

1. Generate your private key `YOUR_PRIVATE_KEY`:
```bash
docker run --rm ghcr.io/semgrep/semgrep-network-broker:latest genkey
```
> _Do not_ share your private key with anyone (including Semgrep).

2. Generate your public key `YOUR_PUBLIC_KEY`:
```bash
echo YOUR_PRIVATE_KEY | docker run --rm -i ghcr.io/semgrep/semgrep-network-broker:latest pubkey
```
> Your public key is safe to share.

### Configure the Broker Settings Page
The Semgrep backend needs your public key to connect to the broker. Your public key is shared in the Broker settings page of your Semgrep organization.
1. Log in to Semgrep AppSec Platform.
2. Navigate to Settings > Broker.
3. Paste your public key `YOUR_PUBLIC_KEY` into the field and click `Add Public Key`.

### Configure the Broker YAML Config File

Create the YAML file that is passed to the broker during execution. The minimum `config.yaml` file has the following contents. Below are instructions to fill in the templated values marked with angle brackets.

```yaml
inbound:
  wireguard:
    privateKey: <YOUR_PRIVATE_KEY>
  <SCM_NAME>:
    baseUrl: <SCM_URL>
    token: <SCM_SECRET>
    allowCodeAccess: true
```

1. YOUR_PRIVATE_KEY: input the wireguard private key [generated earlier](README.md#key-generation).
2. SCM_NAME: input the name of your private network resource. Refer to the table below.
3. SCM_URL: input the URL of your private network resource. Refer to the table below.
4. SCM_SECRET: *Optional. Do not include `token: <SMC_SECRET>` unless you have a special use case requiring it. These tokens are typically many-to-one SCM and are managed in the Semgrep UI not in this config file.

> **NOTE:** if you have multiple SCMs of different or same type [refer here](README.md#configure-access-to-multiple-scms).

#### Accepted SCM Config Values
| Source Code Manager | SCM_NAME | SCM_URL | SCM_SECRET |
| ------------- | -------------| ------------- | ------------- |
| GitLab Server  |  gitlab   | `https://<GITLAB_BASE_URL>/api/v4` | Group Access Token with [`api`](https://semgrep.dev/docs/deployment/connect-scm#connect-to-on-premise-orgs-and-projects) and [`read_repository`](https://semgrep.dev/docs/semgrep-appsec-platform/scm-code-access#required-scm-code-access-scopes) scope |
| GitHub Enterprise Server | github | `https://<GITHUB_BASE_URL>/api/v3`   | Personal Access Token |
| BitBucket DataCenter <v7.17.x | bitbucket | `https://<BITBUCKET_BASE_URL>/rest/api/latest` | [Personal Access Token](https://semgrep.dev/docs/deployment/managed-scanning/bitbucket#bitbucket-data-center) with `PROJECT_ADMIN` permissions |
| BitBucket DataCenter >=v7.18.x. | bitbucket | `https://<BITBUCKET_BASE_URL>/rest/api/latest` | [HTTP Access Token](https://semgrep.dev/docs/deployment/managed-scanning/bitbucket#bitbucket-data-center) with `PROJECT_ADMIN` permissions |
| Azure DevOps Server | azuredevops | `https://<ADO_BASE_URL>/*` | [Personal Access Token](https://semgrep.dev/docs/deployment/managed-scanning/azure#prerequisites-and-permissions) with `Full access` |

> **NOTE**: the SCM_Secret scopes/permissions listed are for setups allowing Semgrep access to Source Code. Downgrade the permissions if your setup does not require code access. For downgraded scopes, refer to the linked documentation.

## Usage
### Supplying the Config File
Config file(s) are passed to the broker with the flag `-c <PATH_TO_CONFIG>`:

Multiple config files can be overlaid on top of each other by passing multiple `-c` args (ex. `semgrep-network-broker -c config1.yaml -c config2.yaml -c config3.yaml`). Note that while maps will be merged together, arrays will be _replaced_.

### Pulling Additional Default Configuration with DEPLOYMENT_ID
On top of your local config file, the broker will need to pull additional configuration information from the Semgrep platform.

This is done with the flag `-d <ORGANIZATION_ID>` using the Semgrep Organization ID [retrieved earlier](README.md#semgrep-organization-id).

### Running the Broker
Here is the recommended default command to run the broker.
- It uses a published broker docker image.
- The config file is assumed to be located at `./config.yaml`.
- It uses your `ORGANIZATION_ID` to pull the default config from Semgrep.
```
docker run --rm-it -v ./config.yaml:/emt/config.yaml ghcr.io/semgrep/semgrep-network-broker:v0.34.0 -c /emt/config.yml -d ORGANIZATION_ID
```
### Other Commands

#### dump

`semgrep-network-broker dump` dumps the current config. This is useful to see what the result of multiple configurations overlays would result in

#### genkey

`semgrep-network-broker genkey` generates a base64 private key and prints to stdout.

#### pubkey

`semgrep-network-broker pubkey` reads a base64 private key from stdin and prints the corresponding base64 public key to stdout.

#### relay

`semgrep-network-broker relay` launches an HTTP server that relays request that match a certain rule.

```yaml
outbound:
  listenPort: 8080
  relay:
    test:
      destinationUrl: https://httpbin.org/anything
      jsonPath: "$.foo"
      equals:
        - bar
```

would result in requests addressed to http://localhost:8080/relay/test being relayed to https://httpbin.org/anything as long as the result of the jsonpath query `$.foo` executed on the request body results in the string `bar`.

Check out an example [here](./examples/github-pr-comment-relay.yaml) for how to use the relay for GitHub PR comments.

You can also define additional relay mappings via the `additionalConfigs` field:

```yaml
outbound:
  listenPort: 8080
  relay:
    test:
      destinationUrl: https://httpbin.org/anything
      jsonPath: "$.foo"
      equals:
        - bar
      additionalConfigs:
        - destinationUrl: https://example.com/fallback
```

The example above would relay traffic to https://httpbin.org/anything if the request body contains `{"foo": "bar"}`, otherwise, it'd relay traffic to `htttps://example.com/fallback`.

## Additional Scenarios
### Enable Logging for Debugging

> **Performance impact** Please enable these settings only while working to identify issues. Otherwise, significant memory in the tunnel is used on large request and response bodies.

The `logging` configuration section allows you to set additional logging options for requests that are proxied through the broker.

```yaml
inbound:
  logging:
    logRequestBody: false # If true, the contents of any proxied HTTP request matching the allowlist will be logged in the request_body field in the proxy.request event
    logResponseBody: false # If true, the contents of any proxied HTTP response will be logged in the response_body field in the proxy.response event
```
#### Logging Traffic to Specific Endpoints
`logRequestBody` and `logResponseBody` can also be set on a per-allowlist basis:

```yaml
inbound:
  allowlist:
    - url: https://httpbin.org/*
      methods: [GET, POST, DELETE]
      logRequestBody: true
      logResponseBody: true
```
#### Check the Logs
You can check the logs with the following commands:
| Deployment | Command |
| -----------| --------|
| Kubernetes | `kubectl logs <POD_NAME>` |
| Docker | `docker logs <CONTAINER_ID>` |

#### Example Log Output
Here's an example log output of `curl -X POST -H "Content-Type: application/json" "https://httpbin.org/anything" -d '{"foo": "bar"}'` being proxied through the network broker:

```
INFO[0006] request.start                                 client_ip="::1" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= user_agent=curl/8.2.1
INFO[0006] proxy.request                                 allowlist_match="https://httpbin.org/*" client_ip="::1" destinationUrl="https://httpbin.org/anything" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= request_body="{\"foo\": \"bar\"}" user_agent=curl/8.2.1
INFO[0006] proxy.response                                allowlist_match="https://httpbin.org/*" client_ip="::1" destinationUrl="https://httpbin.org/anything" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= response_body="{\n  \"args\": {}, \n  \"data\": \"{\\\"foo\\\": \\\"bar\\\"}\", \n  \"files\": {}, \n  \"form\": {}, \n  \"headers\": {\n    \"Accept\": \"*/*\", \n    \"Accept-Encoding\": \"gzip\", \n    \"Content-Length\": \"14\", \n    \"Content-Type\": \"application/json\", \n    \"Host\": \"httpbin.org\", \n    \"User-Agent\": \"curl/8.2.1\", \n    \"X-Amzn-Trace-Id\": \"Root=1-650469a8-0032596526902b563d7e5ebc\"\n  }, \n  \"json\": {\n    \"foo\": \"bar\"\n  }, \n  \"method\": \"POST\", \n  \"origin\": \"::1, ...snip..., ...snip...\", \n  \"url\": \"https://httpbin.org/anything\"\n}\n" user_agent=curl/8.2.1
INFO[0006] request.response                              body_size=511 client_ip="::1" id=1 latency=341.905708ms method=POST path="/proxy/https://httpbin.org/anything" query= status_code=200 user_agent=curl/8.2.1
```
### Configure Access to Multiple SCMs
It is possible to allow access to multiple source code managers (SCM) within a single configuration file. One entry for a given SCM uses the SCM-specific key provided in the configuration file, as shown in the following example for a GitHub Enterprise Server connection:
```yaml
github:
  baseURL: https://GITHUB_BASE_URL/api/v3
  token: GITHUB_PAT
```
Subsequent entries for the same type of SCM require you to modify allowlist and add specific information needed for the HTTP requests. The following is a sample allowlist for additional GitHub Enterprise Servers:
```yaml
allowlist:
 - url: https://GITHUB_BASE_URL/api/v3/repos/:owner/:repo
    methods: [GET]
    setRequestHeaders:
      Authorization: "Bearer GITHUB_PAT"
 - url: https://GITHUB_BASE_URL/api/v3/repos/:owner/:repo/pulls
    methods: [GET]
    setRequestHeaders:
      Authorization: "Bearer GITHUB_PAT"
 - url: https://GITHUB_BASE_URL/api/v3/repos/:owner/:repo/pulls/:number/comments
    methods: [POST]
    setRequestHeaders:
      Authorization: "Bearer GITHUB_PAT"
 - url: https://GITHUB_BASE_URL/api/v3/:owner/:repo/issues/:number/comments
    methods: [POST]
    setRequestHeaders:
      Authorization: "Bearer GITHUB_PAT"
```
### Not using the Default Config Flag
If you are not using the `-d <ORGANIZATION_ID>` flag to [pull the default configuration](README.md#pulling-additional-default-configuration-with-deployment_id), you will need to manually add these values to your configuration YAML file.

These values can be found already customized to your organization on the Broker settings page in the Semgrep Cloud Platform.

If you want to construct them manually you will need to:
1. Add the following config items under `inbound` in your config.
2 Replace the `<HEX_ORG_ID>` with the hexadecimal version of your <ORGANIZATION_ID>. You can use a tool like [Decimal to Hexadecimal converter](https://www.rapidtables.com/convert/number/decimal-to-hex.html) to perform the conversion if needed.

```yaml
inbound:
  wireguard:
    localAddress: fdf0:59dc:33cf:9be8:0:<HEX_ORG_ID>:0:1
    peers:
      - publicKey: 4EqJwDZ8X/qXB5u3Wpo2cxnKlysec93uhRvGWPix0lg=
        endpoint: wireguard.semgrep.dev:51820
        allowedIps: fdf0:59dc:33cf:9be9::1/128
  heartbeat:
    url: http://[fdf0:59dc:33cf:9be9:0000:0000:0000:0001]/ping


### Use of an HttpClient

The `httpClient` configuration section modifies the HTTP client used for proxying requests.

Example:

```yaml
inbound:
  httpClient:
    additionalCACerts: # Optional. Certificates here will be appended to the Root CA trust of the container. Necessary when the SCM(s) the broker interacts with have self-signed certificates.
      - /path/to/custom/cert.pem
    tlsMinVersion: "1.2" # Optional. Valid values: "1.2", "1.3". Defaults to "1.3" if unset.
```

An alternative to stipulating `additionalCACerts:` is setting the `$SSL_CERT_DIR` environment variable at time of container creation.

Example:

```bash
$ docker run \
  ...
  -v /path/containing/your/certs:/certs \ # mount a path from the host machine as a container volume
  -e SSL_CERT_DIR=/certs \ # set the $SSL_CERT_DIR environment variable to the mounted volume
  ...
  -it semgrep-network-broker:latest -c /emt/config.yaml
```

Refer to the [network broker docs on semgrep.dev](https://semgrep.dev/docs/semgrep-ci/network-broker) for more detail on docker setup.

## Broker Allowlist

The `allowlist` configuration section provides finer-grained control over what HTTP requests are allowed to be forwarded out of the broker. By default, the allowlist will automatically be populated and does not need explicit configuration.

Allowlist Behaviour:
- When multiple version of an allowlist item exist, the first matching allowlist item is used.
- No allowlist match means the request will not be proxied.

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

### GitHub

The `github` configuration section simplifies granting Semgrep access to leave PR comments.

Example:

```yaml
inbound:
  github:
    baseUrl: https://github.example.com/api/v3
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Adding a `github` field to the config implicitly adds these endpoints to the allowlist:

<!-- BeginAutogeneratedAllowList:Github -->
- GET `https://github.example.com/api/v3/app`
- GET `https://github.example.com/api/v3/app/hook/config`
- GET `https://github.example.com/api/v3/installation/repositories`
- GET `https://github.example.com/api/v3/organizations`
- GET `https://github.example.com/api/v3/orgs/:org`
- GET `https://github.example.com/api/v3/orgs/:org/hooks`
- GET `https://github.example.com/api/v3/orgs/:org/installation`
- GET `https://github.example.com/api/v3/orgs/:org/members`
- GET `https://github.example.com/api/v3/orgs/:org/repos`
- GET `https://github.example.com/api/v3/orgs/:org/teams`
- GET `https://github.example.com/api/v3/orgs/:org/teams/:team_slug/members`
- GET `https://github.example.com/api/v3/repos/:org/:repo/actions/secrets/public-key`
- GET `https://github.example.com/api/v3/repos/:owner/:repo`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/branches`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/collaborators/:username/permission`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/compare/:basehead`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/contents/.github/workflows/semgrep.yml`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/installation`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/pulls`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/pulls/comments/:comment_id/reactions`
- GET `https://github.example.com/api/v3/user`
- GET `https://github.example.com/api/v3/user/repos`
- GET `https://github.example.com/api/v3/users/:user/installation`
- GET `https://github.example.com/api/v3/users/:user/installation/repositories`
- GET `https://github.example.com/api/v3/users/:username`
- POST `https://github.example.com/api/v3/app-manifests/:code/conversions`
- POST `https://github.example.com/api/v3/app/installations/:id/access_tokens`
- POST `https://github.example.com/api/v3/orgs/:org/hooks`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/check-runs`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/issues/:number/comments`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments/:comment_id/replies`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/statuses/:commit`
- PUT `https://github.example.com/api/v3/repos/:org/:repo/actions/secrets/SEMGREP_APP_TOKEN`
- PUT `https://github.example.com/api/v3/repos/:owner/:repo/contents/.github/workflows/semgrep.yml`
- PATCH `https://github.example.com/api/v3/orgs/:org/hooks/:hook_id`
- PATCH `https://github.example.com/api/v3/repos/:owner/:repo/check-runs/:check_run_id`
- PATCH `https://github.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments/:comment_id`
- PATCH `https://github.example.com/api/v3/repos/:owner/:repo/pulls/comments/:comment_id`
- DELETE `https://github.example.com/api/v3/orgs/:org/hooks/:hook_id`
<!-- EndAutogeneratedAllowList:Github -->

And if `allowCodeAccess` is set, these endpoints are added to the allowlist:

<!-- BeginAutogeneratedAllowList:Github.AllowCodeAccess -->
- GET `https://github.example.com/:owner/:repo/info/refs`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/commits`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/contents`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/contents/*`
- POST `https://github.example.com/:owner/:repo/git-upload-pack`
<!-- EndAutogeneratedAllowList:Github.AllowCodeAccess -->

### GitLab

Similarly, the `gitlab` configuration section grants Semgrep access to leave MR comments.

Example:

```yaml
inbound:
  gitlab:
    baseUrl: https://gitlab.example.com/api/v4
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Adding a `gitlab` field to the config implicitly adds these endpoints to the allowlist:

<!-- BeginAutogeneratedAllowList:Gitlab -->
- GET `https://gitlab.example.com/api/v4/:entity_type/:namespace/projects`
- GET `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- GET `https://gitlab.example.com/api/v4/groups/:namespace/members/all`
- GET `https://gitlab.example.com/api/v4/groups/:namespace/members/all/:user`
- GET `https://gitlab.example.com/api/v4/namespaces/:namespace`
- GET `https://gitlab.example.com/api/v4/personal_access_tokens/self`
- GET `https://gitlab.example.com/api/v4/projects/:project`
- GET `https://gitlab.example.com/api/v4/projects/:project/members/all/:user`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note/award_emoji`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/versions`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/branches`
- POST `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- POST `https://gitlab.example.com/api/v4/projects/:project/hooks`
- POST `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions`
- POST `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes`
- PUT `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- PUT `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion`
- PUT `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note`
- DELETE `https://gitlab.example.com/api/v4/groups/:namespace/hooks/:hook`
- DELETE `https://gitlab.example.com/api/v4/projects/:project/hooks/:hook`
<!-- EndAutogeneratedAllowList:Gitlab -->

And if `allowCodeAccess` is set, these endpoints are added to the allowlist:

<!-- BeginAutogeneratedAllowList:Gitlab.AllowCodeAccess -->
- GET `https://gitlab.example.com/:namespace/:project/info/refs`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/commits`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/compare`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/files/*`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/merge_base`
- POST `https://gitlab.example.com/:namespace/:project/git-upload-pack`
- POST `https://gitlab.example.com/api/v4/projects/:project/statuses/:commit`
<!-- EndAutogeneratedAllowList:Gitlab.AllowCodeAccess -->

### Bitbucket

Similarly, the `bitbucket` configuration section grants Semgrep access to leave MR comments.

```yaml
inbound:
  bitbucket:
    baseUrl: https://bitbucket.example.com/rest/api/latest
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Adding a `bitbucket` field to the config implicitly adds these endpoints to the allowlist:

<!-- BeginAutogeneratedAllowList:Bitbucket -->
- GET `https://bitbucket.example.com/rest/api/latest/application-properties`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/default-branch`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments/:comment`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/webhooks`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/blocker-comments`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/webhooks`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks`
- PUT `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments/:comment`
- PUT `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/webhooks/:webhook`
- PUT `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks/:webhook`
- DELETE `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/webhooks/:webhook`
- DELETE `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks/:webhook`
<!-- EndAutogeneratedAllowList:Bitbucket -->

And if `allowCodeAccess` is set, these endpoints are added to the allowlist:

<!-- BeginAutogeneratedAllowList:Bitbucket.AllowCodeAccess -->
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/browse/*`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/commits`
- GET `https://bitbucket.example.com/scm/:project/:repo/info/refs`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/commit/:commit/builds`
- POST `https://bitbucket.example.com/scm/:project/:repo/git-upload-pack`
<!-- EndAutogeneratedAllowList:Bitbucket.AllowCodeAccess -->

### Azure DevOps

Similarly, the `azuredevops` configuration section grants Semgrep access to azure devops.

```yaml
inbound:
  azureDevOps:
    baseUrl: https://example@dev.azure.com/
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Adding a `gitlab` field to the config implicitly adds these endpoints to the allowlist:

<!-- BeginAutogeneratedAllowList:AzureDevOps -->
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories`
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo`
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests`
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations`
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations/:iterationId/changes`
- GET `https://dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- GET `https://dev.azure.com/:namespace/_apis/connectionData`
- GET `https://dev.azure.com/:namespace/_apis/projects/:project`
- GET `https://vsaex.dev.azure.com/:namespace/_apis/groupentitlements`
- POST `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads`
- POST `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments`
- POST `https://dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- PUT `https://dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- PATCH `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads`
- PATCH `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments/:commentId`
<!-- EndAutogeneratedAllowList:AzureDevOps -->

And if `allowCodeAccess` is set, these endpoints are added to the allowlist:

<!-- BeginAutogeneratedAllowList:AzureDevOps.AllowCodeAccess -->
- GET `https://dev.azure.com/:namespace/:project/_apis/git/pullrequests/:number`
- GET `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/items`
- GET `https://dev.azure.com/:namespace/:project/_git/:repo/info/refs`
- POST `https://dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/commits/:commit/statuses`
- POST `https://dev.azure.com/:namespace/:project/_git/:repo/git-upload-pack`
<!-- EndAutogeneratedAllowList:AzureDevOps.AllowCodeAccess -->
