package metadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const permissiveMaxOutput = 1024 * 1024
const catalogMaxPolicyBytes = 16 * 1024 * 1024

// The helper starts no descendants; Go bounds wall time and output and reaps it.
const permissivePython = `import json, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
try:
    import setools
except ImportError:
    print("SETools Python bindings are unavailable", file=sys.stderr)
    sys.exit(2)
policy = setools.SELinuxPolicy(sys.argv[1])
print(json.dumps({
    "domains": sorted({str(t) for t in setools.TypeQuery(policy, permissive=True).results()}),
    "evaluator_version": "SETools " + setools.__version__,
}))
`

var permissiveTypeName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func catalogPermissiveDomains(root, identity string, run func(string, ...string) ([]byte, error)) (CatalogPermissiveDomains, error) {
	file, err := os.CreateTemp("", "secentral-catalog-policy-*.bin")
	if err != nil {
		return CatalogPermissiveDomains{}, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	policy, err := os.Open(filepath.Join(root, "sys/fs/selinux/policy"))
	if err != nil {
		return CatalogPermissiveDomains{}, err
	}
	defer policy.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(policy, catalogMaxPolicyBytes+1))
	if err != nil {
		return CatalogPermissiveDomains{}, err
	}
	if size == 0 || size > catalogMaxPolicyBytes {
		return CatalogPermissiveDomains{}, errors.New("captured policy size is invalid")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != identity {
		return CatalogPermissiveDomains{}, errors.New("captured policy digest does not match initial policy identity")
	}
	if err := file.Close(); err != nil {
		return CatalogPermissiveDomains{}, err
	}
	output, err := run("python3", "-c", permissivePython, file.Name())
	if err != nil {
		return CatalogPermissiveDomains{}, err
	}
	return parseCatalogPermissiveDomains(output)
}

func parseCatalogPermissiveDomains(output []byte) (CatalogPermissiveDomains, error) {
	result := CatalogPermissiveDomains{Complete: true, ExtractorSemanticsVersion: 1}
	if len(output) > permissiveMaxOutput || !utf8.Valid(output) {
		return CatalogPermissiveDomains{}, errors.New("invalid or oversized permissive extraction output")
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return CatalogPermissiveDomains{}, errors.New("expected permissive extraction object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return CatalogPermissiveDomains{}, errors.New("invalid or duplicate permissive extraction key")
		}
		seen[key] = true
		switch key {
		case "domains":
			err = decoder.Decode(&result.Domains)
		case "evaluator_version":
			err = decoder.Decode(&result.EvaluatorVersion)
		default:
			return CatalogPermissiveDomains{}, errors.New("unknown permissive extraction key")
		}
		if err != nil {
			return CatalogPermissiveDomains{}, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return CatalogPermissiveDomains{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return CatalogPermissiveDomains{}, errors.New("trailing permissive extraction output")
	}
	if err := validateCatalogPermissiveDomains(result); err != nil {
		return CatalogPermissiveDomains{}, err
	}
	return result, nil
}

func validateCatalogPermissiveDomains(family CatalogPermissiveDomains) error {
	if !family.Complete || family.Domains == nil || family.ExtractorSemanticsVersion != 1 {
		return errors.New("effective permissive domain family incomplete or unsupported")
	}
	version := family.EvaluatorVersion
	if !utf8.ValidString(version) || len(version) > 120 || !strings.HasPrefix(version, "SETools ") || strings.TrimSpace(strings.TrimPrefix(version, "SETools ")) == "" || strings.ContainsFunc(version, unicode.IsControl) {
		return errors.New("invalid permissive evaluator version")
	}
	if !slices.IsSorted(family.Domains) {
		return errors.New("permissive domains are not canonical")
	}
	for index, domain := range family.Domains {
		if !permissiveTypeName.MatchString(domain) || index > 0 && family.Domains[index-1] == domain {
			return errors.New("invalid or duplicate permissive domain")
		}
	}
	return nil
}

func permissiveCommandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return boundedPermissiveCommand(ctx, name, args...)
}

func boundedPermissiveCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Env = catalogCommandEnv(os.Environ())
	command.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	var mutex sync.Mutex
	remaining := permissiveMaxOutput
	command.Stdout = &permissiveOutput{&stdout, &mutex, &remaining, cancel}
	command.Stderr = &permissiveOutput{&stderr, &mutex, &remaining, cancel}
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("permissive extraction failed: %w: %s", errors.Join(err, ctx.Err()), stderr.String())
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return stdout.Bytes(), nil
}

type permissiveOutput struct {
	buffer    *bytes.Buffer
	mutex     *sync.Mutex
	remaining *int
	cancel    context.CancelFunc
}

func (output *permissiveOutput) Write(data []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	if len(data) > *output.remaining {
		output.cancel()
		return 0, errors.New("permissive extraction output exceeds 1 MiB")
	}
	*output.remaining -= len(data)
	return output.buffer.Write(data)
}
