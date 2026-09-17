# Security

## Supply chain

Released charts are published as OCI artifacts to `ghcr.io/slauger/charts/` and are:

- **Signed** with [cosign](https://docs.sigstore.dev/cosign/) keyless signing (Sigstore OIDC, no long-lived keys).
- **Accompanied by an SBOM** (SPDX) attached as a cosign attestation.

The remediation content itself is pinned to a specific [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) release in `config/content.yaml` and verified against the upstream SHA512 before the charts are generated, so a tampered or unexpected upstream artifact fails the build.

## Verifying a chart signature

Replace `<chart>` with `compliance-platform`, `compliance-node`, or `compliance-hardening`, and `<version>` with the released version.

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'github.com/slauger/openshift-compliance-remediations' \
  ghcr.io/slauger/charts/<chart>:<version>
```

Verify the SBOM attestation:

```sh
cosign verify-attestation --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'github.com/slauger/openshift-compliance-remediations' \
  ghcr.io/slauger/charts/<chart>:<version>
```

## Reporting a vulnerability

Open a private security advisory via GitHub (Security > Advisories) rather than a public issue.
