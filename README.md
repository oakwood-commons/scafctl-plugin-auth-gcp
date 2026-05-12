# scafctl-plugin-auth-gcp

Google Cloud Platform authentication handler plugin for scafctl.

## Supported Flows

| Flow | Description | Use Case |
|------|-------------|----------|
| `device_code` | OAuth 2.0 device authorization grant | Headless/CI environments |
| `adc` | Application Default Credentials (browser OAuth with PKCE) | Local developer workstations |
| `metadata` | GCE metadata server | Workloads running on GCE/GKE/Cloud Run |
| `service_account` | Service account key JWT assertion | CI/CD with service account JSON keys |
| `workload_identity` | Workload Identity Federation (STS token exchange) | Cross-cloud or OIDC-federated workloads |
| `impersonation` | IAM Credentials API impersonation | Accessing resources as another service account |
| `gcloud_adc` | Reads gcloud's cached ADC credentials | Fallback when gcloud is already authenticated |

## Configuration

The plugin reads configuration from a JSON file at
`$XDG_CONFIG_HOME/scafctl/auth-handlers/auth-gcp.json`:

```json
{
  "client_id": "YOUR_OAUTH_CLIENT_ID.apps.googleusercontent.com",
  "client_secret": "YOUR_OAUTH_CLIENT_SECRET",
  "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
  "project_id": "my-gcp-project"
}
```

All fields are optional. The plugin ships with sensible defaults for public
OAuth clients (similar to gcloud's own client ID).

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
| Provider name | `auth-gcp` |
| Catalog artifact | `auth-gcp` |

The **provider name** is what users reference in solutions (`provider: auth-gcp`).
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
the **auth-gcp** auth handler:

```bash
scafctl auth login auth-gcp
```

Once authenticated, reference it in HTTP requests:

```yaml
resolvers:
  data:
    resolve:
      with:
        - provider: http
          inputs:
            url: https://api.example.com/data
            auth: auth-gcp
```

## Development

```bash
# Run tests
task test

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
scafctl catalog push auth-gcp --version v1.0.0

# Refresh the catalog index so the provider is discoverable
scafctl catalog index push --catalog oci://ghcr.io/<REGISTRY_OWNER>
```

Both steps are required. Publishing the artifact alone does not make the
provider appear in catalog listings.

### CI release workflow

The release workflow needs two kinds of authentication:

1. **Container registry auth** for OCI push operations (`docker login` or equivalent).
2. **scafctl auth** for catalog operations (`scafctl auth login github --flow pat --registry ghcr.io --write-registry-auth`).

Standard `docker login` is not sufficient for `scafctl catalog index push`.

### Required secrets

| Secret | Scopes | Purpose |
|--------|--------|---------|
| `GITHUB_TOKEN` | Default | Build, test, create release |
| `CATALOG_PUSH_TOKEN` | `repo`, `read:packages`, `write:packages` | Publish artifact and refresh catalog index |

Create the publishing secret at the org or repo level:

```bash
gh secret set CATALOG_PUSH_TOKEN --org <ORG> --repos scafctl-plugin-auth-gcp --body "$TOKEN"
```

### Token strategy

For official providers, use a machine account or GitHub App for the publishing
token rather than a personal account. This avoids tying release capability to
an individual developer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.