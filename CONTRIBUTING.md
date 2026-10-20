# Contributing

Feedback, bug reports, documentation improvements, and pull requests are welcome.
For larger changes, open an issue first to discuss the approach.

## Development

Use the Go version specified in `go.mod`. See [README.md](README.md)
for an overview and [TEST.md](TEST.md) for testing instructions.

Keep the agent small: prefer the standard library, preserve raw audit
evidence, and leave event interpretation to the server. Changes to the
ingestion protocol must consider compatibility and be documented.

## Pull requests

- Keep changes focused and follow the existing code style.
- Add or update tests for behavior changes.
- Format changed Go files with `gofmt` and run `go test ./...`.
- Describe the problem, your changes, and how you tested them.

Remove credentials and sensitive host information from reports and examples.
