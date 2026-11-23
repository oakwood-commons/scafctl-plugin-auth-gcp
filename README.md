# scafctl-plugin-auth-gcp

Google Cloud Platform authentication handler plugin for scafctl.

## Supported Flows

| Flow | Description | Use Case |
|------|-------------|----------|
| `interactive` | Application Default Credentials (browser OAuth with PKCE) | Local developer workstations |
| `device_code` | OAuth 2.0 device authorization grant | Headless/CI environments |
| `metadata` | GCE metadata server | Workloads running on GCE/GKE/Cloud Run |
| `service_principal` | Service account key JWT assertion | CI/CD with service account JSON keys |
| `workload_identity` | Workload Identity Federation (STS token exchange) | Cross-cloud or OIDC-federated workloads |
| `gcloud_adc` | Reads gcloud's cached ADC credentials | Fallback when gcloud is already authenticated |

Service account impersonation (`impersonateServiceAccount`) can be combined with any credential source above to mint short-lived tokens via the IAM Credentials API.

## Configuration

Configure `auth.gcp` in your scafctl `config.yaml`:

```yaml
auth:
  gcp:
    clientId: "YOUR_OAUTH_CLIENT_ID.apps.googleusercontent.com"
    clientSecret: "YOUR_OAUTH_CLIENT_SECRET"
    defaultScopes:
      - openid
      - email
      - profile
      - https://www.googleapis.com/auth/cloud-platform
    project: my-gcp-project
    impersonateServiceAccount: deploy@my-gcp-project.iam.gserviceaccount.com
    activeProfile: work
    profiles:
      work:
        project: work-gcp-project
        serviceAccountKeyFile: /path/to/work-sa.json
      personal:
        project: personal-gcp-project
```

Keys under `auth.gcp` (and `auth.gcp.profiles.<name>`):

| Key | Default | Notes |
|-----|---------|-------|
| `clientId` | Google public ADC client ID | OAuth 2.0 client ID for interactive and device-code flows |
| `clientSecret` | Google public ADC client secret | OAuth 2.0 client secret |
| `defaultScopes` | `openid`, `email`, `profile`, `https://www.googleapis.com/auth/cloud-platform` | Default OAuth scopes requested during login |
| `impersonateServiceAccount` | *(empty)* | Service account email to impersonate on token requests |
| `project` | *(empty)* | Default GCP project ID recorded in session metadata |
| `serviceAccountKeyFile` | *(empty)* | Path to service account JSON key; takes precedence over `GOOGLE_APPLICATION_CREDENTIALS` |
| `externalAccountFile` | *(empty)* | Path to Workload Identity Federation JSON config; takes precedence over `GOOGLE_EXTERNAL_ACCOUNT` |
| `httpClient` | 30s timeout, 3 retries, cache off | Optional HTTP client overrides (`timeout`, `retryMax`, `enableCircuitBreaker`, etc.) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_EXTERNAL_ACCOUNT` | Path to Workload Identity Federation external account JSON file |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account key JSON file (or `authorized_user` gcloud ADC JSON file) |
| `CLOUDSDK_CONFIG` | Custom gcloud configuration directory for `gcloud_adc` discovery |
| `GCE_METADATA_HOST` | Loopback/metadata override for the GCE metadata server |
| `BROWSER` | Preferred browser executable or fallback list for interactive login when `--browser` is not passed |

## Security Note

The `metadata` flow communicates with the GCE metadata server at
`169.254.169.254`. This uses a dedicated `net/http` client (not `httpc`)
because httpc's SSRF protection blocks link-local addresses by design.
The metadata client is hardcoded to only contact the metadata IP and
includes the required `Metadata-Flavor: Google` header.

## Names

This plugin uses the following names across different surfaces:

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-auth-gcp` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-auth-gcp` |
| Binary | `scafctl-plugin-auth-gcp` |
| Provider name | `gcp` |
| Catalog artifact | `gcp` |

The **provider name** is what users reference in solutions (`provider: gcp`).
It comes from the RPC contract (`GetProviders` / `GetProviderDescriptor`), not from
the binary filename.

## Installation

```bash
# Build from source
task build

# Or download from releases
gh release download --repo github.com/oakwood-commons/scafctl-plugin-auth-gcp
```

## Usage

Register this plugin in your scafctl configuration, then use
the **gcp** auth handler:

```bash
# Interactive browser login (default)
scafctl auth login gcp

# Login to a named profile
scafctl auth login gcp --profile work

# Open a specific browser for interactive login
scafctl auth login gcp --flow interactive --browser chrome

# Pin the localhost OAuth callback port (e.g. for SSH port forwarding)
scafctl auth login gcp --flow interactive --callback-port 8400
```

### Interactive OAuth Callback Pages

During `interactive` browser login, the localhost callback server uses deferred completion (`oauth.WithDeferredCompletion`) and renders host-supplied Blueprint HTML pages (`ProviderConfig.AuthCallbackPages` passed via `ConfigureAuthHandler`) when configured, falling back to `oauth-helpers` built-in dark-mode cards with strict `Content-Security-Policy` headers otherwise:

- **HTTP `200 OK`** (`SuccessHTML`): rendered only after authorization code exchange, ID token/claims verification, and credential persistence all succeed.
- **HTTP `503 Service Unavailable`** (`FailureHTML`): rendered when post-callback token exchange, claims validation, context cancellation, or credential storage fails, without clobbering any previously authenticated session.
- **HTTP `400 Bad Request` / `403 Forbidden`** (`FailureHTML`): rendered on direct OAuth authorization errors or mismatched OAuth `state` parameters.

Once authenticated, reference it in HTTP requests:

```yaml
resolvers:
  data:
    resolve:
      with:
        - provider: http
          inputs:
            url: https://api.example.com/data
            auth: gcp
```

## Development

```bash
# Run tests
task test

# Run tests with race detector
task test:race

# Run linter
task lint

# Build
task build

# Full CI pipeline (lint + test + build)
task ci
```

## Release

### Publishing to a catalog

A tagged release should publish both the provider artifact and refresh the
catalog index:

```bash
# Publish the provider artifact
scafctl catalog push gcp --version v1.0.0

# Refresh the catalog index so the provider is discoverable
scafctl catalog index push --catalog oci://ghcr.io/<REGISTRY_OWNER>
```

Both steps are required. Publishing the artifact alone does not make the
provider appear in catalog listings.

### CI release workflow

The release workflow uses `GITHUB_TOKEN` (automatically provided) for both
GitHub Release creation and OCI pushes to ghcr.io. The job's `packages: write`
permission grants the token registry access.

### Required secrets

| Secret | Scopes | Purpose |
|--------|--------|---------|
| `GITHUB_TOKEN` | Default + `packages: write` | Build, test, create release, push OCI artifacts |

No additional secrets are required.

### Token strategy

For official providers, use a machine account or GitHub App for the publishing
token rather than a personal account. This avoids tying release capability to
an individual developer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
