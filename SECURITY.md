# Security Policy

Bulwark is production-oriented open-source security software from
Joshua Matos and DoctrineOne Industries. It is intended to be adopted into real
applications with the environment-specific controls described in the production
adoption guide.

## Supported Versions

Security fixes are accepted for the current `main` branch. Public releases may
also receive patch tags when the project begins publishing versioned releases.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately first.

If this repository is hosted on GitHub, use GitHub's private vulnerability
reporting feature when it is enabled. Otherwise, contact the maintainer through
the public profile associated with the repository and provide:

- the affected module and files
- a concise impact statement
- reproduction steps or a minimal proof of concept
- whether the issue requires any dependency, configuration, or runtime condition

Do not open a public issue with exploit details until the issue has been triaged.

## Scope

In scope:

- bugs in the reference code that weaken the documented security boundary
- unsafe default configuration in the examples
- dependency or build-chain risks that affect this repository
- documentation that could lead readers to deploy an unsafe pattern

Out of scope:

- vulnerabilities in unrelated systems copied from this example
- claims that require production infrastructure not present in this repository
- social engineering, spam, denial-of-service, or destructive testing
- requests for production compliance certification without a separate agreement

## Cryptography And Compliance Notes

Cryptographic examples demonstrate API shape, provider seams, and migration
strategy. Algorithm names and FIPS-approved algorithm identities are not claims
that a given runtime provider or deployment is FIPS-validated. Production users
must validate their own providers, keys, modules, policies, and operating
environment.

## Public Data Rule

Do not include real secrets, customer identifiers, tenant names, hostnames,
tokens, private keys, credentials, or internal endpoint values in reports,
issues, pull requests, tests, or examples. Use neutral fictional values.
