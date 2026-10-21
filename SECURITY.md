# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Email **security@antispamguy.org** with:

- a description of the issue and its potential impact
- steps to reproduce it
- the affected commit or version
- any suggested mitigation, if you have one
- your name and contact details (optional — reports may be anonymous)

If you prefer encrypted email, ask for our PGP key in your first message.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgment of receipt | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Status updates during investigation | Weekly, at minimum |
| Fix released or mitigation published | As soon as practical, coordinated with you |

We follow coordinated disclosure and credit reporters unless they prefer to remain
anonymous.

## Scope

In scope: the code in this repository — both the Go and the Node.js
implementations — and anything that lets a registry operator or an observer learn
which credential a verifier is checking, forge or hide a revocation, or sign as the
service.

Out of scope: a specific operator's deployment of this code (report those to that
operator), and issues in upstream dependencies without exploitable impact here
(report those upstream).

Weaknesses in the protocol itself rather than this implementation belong to the
Identity Agent project:
https://github.com/LF-Decentralized-Trust-labs/identity-bot/blob/main/SECURITY.md

## Supported versions

Security fixes are applied to `main` only until a stable release is published.
