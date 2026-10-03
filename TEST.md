# Testing

Install the Go version specified by `go.mod`, then run from the repository
root:

```sh
gofmt -w $(git ls-files '*.go')
go test ./...
```

Before submitting a change, format changed Go files with `gofmt` and run the
test suite. Most tests do not require SELinux to be enabled.
