# Changelog

All notable changes to this project will be documented in this file.

This project follows the spirit of Keep a Changelog and uses semantic versioning
once public version tags begin.

## [Unreleased]

### Added

- Public release documentation: security policy, contribution guide, changelog,
  and public release checklist.
- Production adoption guide and stronger public positioning as a Java 21
  security toolkit for multi-tenant SaaS applications.
- Maven publication metadata for local/internal artifact consumption.
- CI hardening for build/test verification and pull-request dependency review.
- Crypto-agility library split into `crypto-agility-core`,
  `crypto-agility-spring-boot-starter`, and `crypto-agility-testkit`, with the
  original `crypto-agility` artifact retained as a compatibility aggregate.

## [0.1.0] - 2026-06-05

### Added

- Initial public-ready reference modules:
  - `shared`
  - `tenant-isolation`
  - `layered-authorization`
  - `edge-perimeter`
  - `supply-chain`
  - `crypto-agility`
- ADR-backed documentation for the layered security posture.
- Test coverage for tenant isolation, authorization, perimeter controls,
  supply-chain checks, and crypto-agility seams.
