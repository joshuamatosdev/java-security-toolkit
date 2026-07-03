# Security Policy

This toolkit is open-source security software. It is production-oriented. Joshua Matos and DoctrineOne Industries build it.

Adopt it into real applications. Add the environment-specific controls. The production adoption guide describes them.

## Supported Versions

We take security fixes on `main`. Public releases may get patch tags. That starts with versioned releases.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately first.

Is this repository hosted on GitHub? Use GitHub's private vulnerability reporting feature. Use it when it is enabled.

Otherwise, contact the maintainer another way. Use the repository's public profile. Then provide these details:

- The affected module and files.
- A concise impact statement.
- Reproduction steps. Or a minimal proof of concept.
- Does it need a special condition? Like a dependency, configuration, or runtime.

Do not post exploit details publicly. Wait until we triage the issue.

## Scope

In scope:

- Reference-code bugs. They weaken the documented security boundary.
- Unsafe default configuration in the examples.
- Dependency or build-chain risks here.
- Docs that invite an unsafe pattern.

Out of scope:

- Vulnerabilities in systems that copied this.
- Claims that need absent production infrastructure.
- Social engineering, spam, denial-of-service, destructive testing.
- Compliance certification without a separate agreement.

## Cryptography And Compliance Notes

Crypto examples show three things. API shape. Provider seams. Migration strategy.

Algorithm names carry no validation claim. FIPS-approved algorithm identities carry none either. They do not prove FIPS validation. Not for any runtime provider. Not for any deployment.

Production users must validate their setup. Providers. Keys. Modules. Policies. Operating environment.

## Public Data Rule

Never include real sensitive values. That means secrets and customer identifiers. Also tenant names and hostnames. Also tokens and private keys. Also credentials and internal endpoint values. Keep them out of every place. Reports. Issues. Pull requests. Tests. Examples. Use neutral fictional values instead.
