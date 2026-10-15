package metadata

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPermissiveExtractionResultValidation(t *testing.T) {
	for _, domains := range []string{`[]`, `["a_t","z_t"]`} {
		result, err := parseCatalogPermissiveDomains([]byte(`{"domains":` + domains + `,"evaluator_version":"SETools 4.5.1"}`))
		if err != nil || !result.Complete || result.Domains == nil {
			t.Fatalf("result = %#v, err = %v", result, err)
		}
	}
	for _, output := range []string{
		`{`, `null`, `[]`, `{}`, `{"domains":null,"evaluator_version":"SETools 4"}`,
		`{"domains":[],"domains":[],"evaluator_version":"SETools 4"}`,
		`{"domains":[],"evaluator_version":"SETools 4","extra":1}`,
		`{"domains":[],"evaluator_version":"SETools 4"} garbage`,
		`{"domains":[],"evaluator_version":null}`,
		`{"domains":[],"evaluator_version":"SETools "}`,
		`{"domains":[],"evaluator_version":"SETools 4\n"}`,
		`{"domains":["a_t",null],"evaluator_version":"SETools 4"}`,
		`{"domains":["z_t","a_t"],"evaluator_version":"SETools 4"}`,
		`{"domains":["a_t","a_t"],"evaluator_version":"SETools 4"}`,
		`{"domains":["bad-name"],"evaluator_version":"SETools 4"}`,
		`{"domains":[""],"evaluator_version":"SETools 4"}`,
		strings.Repeat(" ", permissiveMaxOutput+1), string([]byte{0xff}),
	} {
		if _, err := parseCatalogPermissiveDomains([]byte(output)); err == nil {
			t.Fatalf("accepted invalid output %.150q", output)
		}
	}
}

func TestPermissiveCaptureIdentityAndCleanup(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	for _, fail := range []bool{false, true} {
		var path string
		run := func(name string, args ...string) ([]byte, error) {
			path = args[len(args)-1]
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("private capture: %v, %v", info, err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "test policy" || name != "python3" {
				t.Fatalf("capture = %q, err = %v", data, err)
			}
			if fail {
				return nil, errors.New("missing SETools")
			}
			return []byte(`{"domains":[],"evaluator_version":"SETools 4"}`), nil
		}
		identity, _ := catalogTestIdentity(nil)
		_, err := catalogPermissiveDomains(catalogFixtureRoot(t), identity, run)
		if (err != nil) != fail || path == "" {
			t.Fatalf("path = %q, err = %v", path, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary policy still exists: %v", err)
		}
	}
	for _, content := range []string{"", "other policy", strings.Repeat("x", catalogMaxPolicyBytes+1)} {
		root := catalogFixtureRoot(t)
		writeFixture(t, root, "/sys/fs/selinux/policy", content)
		identity, _ := catalogTestIdentity(nil)
		_, err := catalogPermissiveDomains(root, identity, func(string, ...string) ([]byte, error) {
			t.Fatal("must not query an invalid capture")
			return nil, nil
		})
		if err == nil {
			t.Fatal("accepted invalid capture")
		}
	}
	entries, err := os.ReadDir(os.TempDir())
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files left behind: %v, %v", entries, err)
	}
}

func TestPermissiveCatalogValidationAndDigest(t *testing.T) {
	for name, mutate := range map[string]func(*CatalogArtifact){
		"old semantics":          func(a *CatalogArtifact) { a.Catalog.CollectorSemanticsVersion = 3 },
		"missing family":         func(a *CatalogArtifact) { a.Catalog.Families.EffectivePermissiveDomains = CatalogPermissiveDomains{} },
		"incomplete":             func(a *CatalogArtifact) { a.Catalog.Families.EffectivePermissiveDomains.Complete = false },
		"unsupported extraction": func(a *CatalogArtifact) { a.Catalog.Families.EffectivePermissiveDomains.ExtractorSemanticsVersion = 2 },
		"tampered domains":       func(a *CatalogArtifact) { a.Catalog.Families.EffectivePermissiveDomains.Domains = []string{"other_t"} },
		"tampered tool version":  func(a *CatalogArtifact) { a.Catalog.Families.EffectivePermissiveDomains.EvaluatorVersion = "SETools 5" },
	} {
		t.Run(name, func(t *testing.T) {
			a := testCatalogArtifact(t)
			mutate(&a)
			if err := ValidateCatalog(a); err == nil {
				t.Fatal("accepted invalid catalog")
			}
		})
	}
	a := testCatalogArtifact(t)
	a.Catalog.Families.EffectivePermissiveDomains.Domains = []string{"a_t", "z_t"}
	setCatalogDigest(t, &a)
	slices.Reverse(a.Catalog.Families.EffectivePermissiveDomains.Domains)
	digest, err := catalogDigest(a.Catalog)
	if err != nil || digest != a.ContentDigest || ValidateCatalog(a) == nil {
		t.Fatalf("noncanonical membership: digest = %q, err = %v", digest, err)
	}
	a.Catalog.Families.EffectivePermissiveDomains.Domains = []string{}
	setCatalogDigest(t, &a)
	if err := ValidateCatalog(a); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedPermissiveHelper(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is unavailable")
	}
	// Exercise the actual embedded helper's query contract without system SETools.
	stub := `import sys, types
class Policy:
    def __init__(self, path):
        assert path == "exact-captured-policy"
class Query:
    def __init__(self, policy, *, permissive):
        assert isinstance(policy, Policy) and permissive is True
    def results(self):
        return ["z_t", "a_t", "a_t"]
sys.modules["setools"] = types.SimpleNamespace(SELinuxPolicy=Policy, TypeQuery=Query, __version__="test-version")
`
	output, err := boundedPermissiveCommand(t.Context(), python, "-c", stub+permissivePython, "exact-captured-policy")
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseCatalogPermissiveDomains(output)
	if err != nil || !slices.Equal(result.Domains, []string{"a_t", "z_t"}) || result.EvaluatorVersion != "SETools test-version" {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
}

func TestCollectCatalogRefusesPermissiveExtractionFailures(t *testing.T) {
	for _, output := range []string{"tool failure", `{`, `{"domains":null,"evaluator_version":"SETools 4"}`} {
		base := catalogRunner(nil)
		run := func(name string, args ...string) ([]byte, error) {
			if name == "python3" {
				if output == "tool failure" {
					return nil, errors.New("tool failure")
				}
				return []byte(output), nil
			}
			return base(name, args...)
		}
		artifact, _, err := collectCatalog(catalogFixtureRoot(t), time.Now(), run, catalogTestIdentity)
		if err == nil || artifact.ContentDigest != "" {
			t.Fatalf("extraction failure produced a catalog: %#v, %v", artifact, err)
		}
	}
}

func TestBoundedPermissiveProcess(t *testing.T) {
	// Use the test binary so these failure checks need neither Python nor SELinux.
	if mode := os.Getenv("SECENTRAL_PERMISSIVE_TEST"); mode != "" {
		switch mode {
		case "success":
			os.Stdout.WriteString("ok")
		case "failure":
			os.Exit(2)
		case "timeout":
			time.Sleep(time.Minute)
		case "overflow":
			os.Stdout.WriteString(strings.Repeat("x", permissiveMaxOutput))
			os.Stderr.WriteString("too much")
		}
		os.Exit(0)
	}
	for _, mode := range []string{"success", "failure", "timeout", "overflow", "missing"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SECENTRAL_PERMISSIVE_TEST", mode)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if mode == "timeout" {
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			binary := os.Args[0]
			if mode == "missing" {
				binary = filepath.Join(t.TempDir(), "missing-python")
			}
			output, err := boundedPermissiveCommand(ctx, binary, "-test.run=^TestBoundedPermissiveProcess$")
			if mode == "success" {
				if err != nil || string(output) != "ok" {
					t.Fatalf("output = %q, err = %v", output, err)
				}
			} else if err == nil || len(output) != 0 {
				t.Fatalf("failed process yielded output: %q, %v", output, err)
			}
		})
	}
}
