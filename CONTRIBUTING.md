# Contributing

Contributions are welcome — bug reports, fixes, and other implementations of the
protocol alike.

## Developer Certificate of Origin

Every commit must carry a sign-off certifying that you wrote the change or have the
right to submit it under this project's licence, as set out in the
[Developer Certificate of Origin](https://developercertificate.org/):

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it for you. Pull requests containing commits without a valid
sign-off cannot be merged.

## Before opening a pull request

- `go build ./... && go vet ./... && go test ./...`
- A change to the wire protocol belongs first in the Identity Agent project's
  ADRs: https://github.com/LF-Decentralized-Trust-labs/identity-bot/tree/main/docs/adr

## Licence

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
