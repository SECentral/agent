package metadata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectFromFixture(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/machine-id", "machine-one\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "boot-one\n")
	writeFixture(t, root, "/etc/os-release", "ID=fedora\nVERSION_ID=44\nNAME=Fedora\n")
	writeFixture(t, root, "/etc/selinux/config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
	writeFixture(t, root, "/sys/fs/selinux/enforce", "1\n")
	writeFixture(t, root, "/sys/fs/selinux/policyvers", "33\n")

	metadata, err := collect(root, "test-host", func() (string, error) { return "6.1.0-test", nil })
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID == "" || metadata.ID == "machine-one" {
		t.Fatalf("unexpected host id %q", metadata.ID)
	}
	if metadata.Hostname != "test-host" || metadata.BootID != "boot-one" {
		t.Fatalf("unexpected identity: %#v", metadata)
	}
	if metadata.Platform.OSID != "fedora" || metadata.Platform.OSVersion != "44" || metadata.Platform.Kernel != "6.1.0-test" {
		t.Fatalf("unexpected platform: %#v", metadata.Platform)
	}
	if !metadata.SELinux.Enabled || metadata.SELinux.Enforcement != Enforcing {
		t.Fatalf("unexpected selinux state: %#v", metadata.SELinux)
	}
	if metadata.SELinux.ConfiguredPolicyType == nil || *metadata.SELinux.ConfiguredPolicyType != "targeted" {
		t.Fatalf("missing configured policy type: %#v", metadata.SELinux)
	}
	if metadata.SELinux.KernelPolicyVersion == nil || *metadata.SELinux.KernelPolicyVersion != 33 {
		t.Fatalf("missing policy version: %#v", metadata.SELinux)
	}
}

func TestCollectIdentityReadsOnlyHostAndBootIDs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/machine-id", "machine-one\n")
	writeFixture(t, root, "/proc/sys/kernel/random/boot_id", "boot-one\n")

	identity, err := CollectIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID == "" || identity.BootID != "boot-one" {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.SELinux.Enabled || identity.SELinux.Policy.FileContexts != nil || identity.SELinux.Booleans != nil {
		t.Fatalf("identity collection included host state: %#v", identity.SELinux)
	}
}

func TestReadPolicyArtifactHashesTheUploadedBytes(t *testing.T) {
	root := t.TempDir()
	policy := []byte("policy fixture")
	writeFixture(t, root, "/sys/fs/selinux/policy", string(policy))

	artifact, identity, err := ReadPolicyArtifact(root)
	if err != nil || string(artifact) != string(policy) {
		t.Fatalf("artifact = %q, err = %v", artifact, err)
	}
	digest := sha256.Sum256(policy)
	if want := "sha256:" + hex.EncodeToString(digest[:]); identity != want {
		t.Fatalf("identity = %q, want %q", identity, want)
	}
}

func TestCollectDegradesForMissingAndMalformedSources(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=fedora\nmalformed\n")
	writeFixture(t, root, "/sys/fs/selinux/enforce", "banana\n")
	writeFixture(t, root, "/sys/fs/selinux/policyvers", "not-a-number\n")

	metadata, err := collect(root, "test-host", func() (string, error) { return "", errors.New("kernel unavailable") })
	if err == nil || !strings.Contains(err.Error(), "os-release") || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("expected diagnostics, got %v", err)
	}
	if metadata.SELinux.Enforcement != Unknown || metadata.SELinux.KernelPolicyVersion != nil {
		t.Fatalf("malformed values invented state: %#v", metadata.SELinux)
	}
	if metadata.SELinux.ConfiguredPolicyType != nil || metadata.ID != "" {
		t.Fatalf("missing values were not left unavailable: %#v", metadata)
	}
}

func TestDisabledSELinuxIsExplicit(t *testing.T) {
	metadata, err := collect(t.TempDir(), "test-host", func() (string, error) { return "kernel", nil })
	if err == nil {
		t.Fatal("expected missing fixture diagnostics")
	}
	if metadata.SELinux.Enabled || metadata.SELinux.Enforcement != Disabled {
		t.Fatalf("unexpected disabled state: %#v", metadata.SELinux)
	}
}

func TestSELinuxReadFailureIsUnknownNotDisabled(t *testing.T) {
	metadata, diagnostics := collectSELinuxWithReader(func(string) (string, error) {
		return "", os.ErrPermission
	}, nil)
	if metadata.Enforcement != Unknown || len(diagnostics) != 1 {
		t.Fatalf("unexpected read failure result: %#v, %v", metadata, diagnostics)
	}
}

func TestParsePolicyModulesReturnsHigherPriorityModules(t *testing.T) {
	modules := parsePolicyModules("100 base 1.0\n400 local_policy 2.3\ninvalid line\n")
	if len(modules) != 1 || modules[0].Name != "local_policy" || modules[0].Priority != 400 || modules[0].Version != "2.3" || modules[0].Provenance != "unknown" {
		t.Fatalf("modules = %#v", modules)
	}
}

func TestParseFileContextsPreservesTypedMappings(t *testing.T) {
	output := "SELinux fcontext                 type               Context\n" +
		"/var/www(/.*)?                    all files          system_u:object_r:httpd_sys_content_t:s0\n" +
		"/srv/app                         directory          system_u:object_r:var_t:s0\n"

	mappings, diagnostics := parseFileContexts(output, nil)

	if len(diagnostics) != 0 || len(mappings) != 2 {
		t.Fatalf("mappings = %#v, diagnostics = %#v", mappings, diagnostics)
	}
	if mappings[0].Pattern != "/srv/app" || mappings[0].FileType != "directory" || mappings[0].Context != "system_u:object_r:var_t:s0" || mappings[0].Provenance != "distribution" {
		t.Fatalf("unexpected first mapping: %#v", mappings[0])
	}
}

func TestParseFileContextsReportsMalformedEntries(t *testing.T) {
	mappings, diagnostics := parseFileContexts("/valid system_u:object_r:var_t:s0\nmalformed\n", nil)

	if len(mappings) != 1 || len(diagnostics) != 1 {
		t.Fatalf("mappings = %#v, diagnostics = %#v", mappings, diagnostics)
	}
}

func TestParseBooleanOutputsPreservesRuntimeAndReportedDefaults(t *testing.T) {
	current, currentDiagnostics := parseCurrentBooleans("httpd_can_network_connect --> on\nvirt_use_nfs --> off\n")
	defaults, defaultDiagnostics := parsePersistentBooleans("SELinux boolean State Default\nhttpd_can_network_connect (on , off) Allow network\nvirt_use_nfs (off , off) Allow NFS\n")
	if len(currentDiagnostics) != 0 || len(defaultDiagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v %v", currentDiagnostics, defaultDiagnostics)
	}
	if !current["httpd_can_network_connect"] || current["virt_use_nfs"] {
		t.Fatalf("current = %#v", current)
	}
	if defaults["httpd_can_network_connect"].Value || defaults["virt_use_nfs"].Value {
		t.Fatalf("defaults = %#v", defaults)
	}
	if defaults["httpd_can_network_connect"].Description != "Allow network" {
		t.Fatalf("description = %#v", defaults["httpd_can_network_connect"])
	}
}

func TestCollectBooleanInventoryKeepsEachBooleanValue(t *testing.T) {
	status, booleans, diagnostics := collectBooleanInventoryWithRunner(func(name string, _ ...string) ([]byte, error) {
		if name == "getsebool" {
			return []byte("first --> on\nsecond --> off\n"), nil
		}
		return []byte("SELinux boolean State Default\nfirst (on , off) First\nsecond (off , on) Second\n"), nil
	}, nil)
	if status != "observed" || len(diagnostics) != 0 {
		t.Fatalf("status = %q, diagnostics = %v", status, diagnostics)
	}
	if booleans[0].Current == nil || booleans[0].Default == nil || !*booleans[0].Current || *booleans[0].Default || booleans[1].Current == nil || booleans[1].Default == nil || *booleans[1].Current || !*booleans[1].Default {
		t.Fatalf("booleans = %#v", booleans)
	}
}

func TestParseBooleanOutputsReportsMalformedEntries(t *testing.T) {
	values, diagnostics := parseCurrentBooleans("good --> on\nbad output\n")
	if !values["good"] || len(diagnostics) != 1 {
		t.Fatalf("values = %#v, diagnostics = %#v", values, diagnostics)
	}
}

func TestCollectBooleanInventoryReportsUnavailableTooling(t *testing.T) {
	status, booleans, diagnostics := collectBooleanInventoryWithRunner(func(string, ...string) ([]byte, error) {
		return nil, errors.New("not installed")
	}, nil)

	if status != "unavailable" || len(booleans) != 0 || len(diagnostics) != 1 {
		t.Fatalf("status = %q, booleans = %#v, diagnostics = %#v", status, booleans, diagnostics)
	}
}

func TestCollectBooleanInventoryPreservesPartialValuesAsUnknown(t *testing.T) {
	status, booleans, diagnostics := collectBooleanInventoryWithRunner(func(name string, _ ...string) ([]byte, error) {
		if name == "getsebool" {
			return []byte("virt_use_nfs --> off\n"), nil
		}
		return nil, errors.New("not installed")
	}, nil)

	if status != "observed" || len(booleans) != 1 || booleans[0].Status != "unknown" || booleans[0].Current == nil || *booleans[0].Current || booleans[0].Default != nil || len(diagnostics) != 1 {
		t.Fatalf("status = %q, booleans = %#v, diagnostics = %#v", status, booleans, diagnostics)
	}
}

func TestCollectBooleanInventoryReportsUnknownForEmptyOutput(t *testing.T) {
	status, booleans, diagnostics := collectBooleanInventoryWithRunner(func(string, ...string) ([]byte, error) {
		return nil, nil
	}, nil)

	if status != "unknown" || len(booleans) != 0 || len(diagnostics) != 0 {
		t.Fatalf("status = %q, booleans = %#v, diagnostics = %#v", status, booleans, diagnostics)
	}
}

func TestPortInventoryReconcilesCanonicalRangesAndCompleteLocalProvenance(t *testing.T) {
	effective := "SELinux Port Type Proto Port Number\n" +
		"http_port_t tcp 443, 80,81, 23451-23455\n" +
		"http_cache_port_t tcp 23456\n"
	local := "SELinux Port Type Proto Port Number\n" +
		"http_cache_port_t tcp 23456\n" +
		"http_port_t tcp 23451\n"

	inventory, diagnostics := collectPortInventoryWithRunner(func(name string, args ...string) ([]byte, error) {
		if args[2] == "-C" {
			return []byte(local), nil
		}
		return []byte(effective), nil
	}, nil)
	if len(diagnostics) != 0 || inventory.Status != "observed" || inventory.LocalClassificationStatus != "observed" {
		t.Fatalf("diagnostics = %v", diagnostics)
	}
	mappings := inventory.Mappings
	if got := mappings[0]; got.Type != "http_cache_port_t" || got.Protocol != "tcp" || len(got.Ports) != 1 || got.Ports[0] != (PortRange{Start: 23456, End: 23456, Provenance: "custom"}) {
		t.Fatalf("unexpected cache mapping: %#v", got)
	}
	if got := mappings[1]; got.Type != "http_port_t" || len(got.Ports) != 4 {
		t.Fatalf("unexpected http mapping: %#v", got)
	}
	if got := mappings[1].Ports; got[0] != (PortRange{Start: 80, End: 81, Provenance: "not_confirmed_custom"}) || got[1] != (PortRange{Start: 443, End: 443, Provenance: "not_confirmed_custom"}) || got[2] != (PortRange{Start: 23451, End: 23451, Provenance: "custom"}) || got[3] != (PortRange{Start: 23452, End: 23455, Provenance: "not_confirmed_custom"}) {
		t.Fatalf("unexpected range provenance: %#v", got)
	}

	for _, port := range []uint16{80, 81, 443, 23451, 23454, 23456} {
		if got, want := resolvePortType(mappings, "tcp", port), resolvePortTypeFromText(effective, "tcp", port); got != want {
			t.Fatalf("port %d resolved to %q, want %q", port, got, want)
		}
	}
}

func TestPortInventoryPreservesEmptyUnavailablePartialAndUnknownEvidence(t *testing.T) {
	header := "SELinux Port Type Proto Port Number\n"
	empty, diagnostics := collectPortInventoryWithRunner(func(string, ...string) ([]byte, error) { return []byte(header), nil }, nil)
	if len(diagnostics) != 0 || empty.Status != "observed" || len(empty.Mappings) != 0 {
		t.Fatalf("empty = %#v, diagnostics = %v", empty, diagnostics)
	}
	encoded, err := json.Marshal(PolicyMetadata{PortInventory: empty})
	if err != nil || !strings.Contains(string(encoded), `"mappings":[]`) {
		t.Fatalf("observed-empty JSON = %s, err = %v", encoded, err)
	}
	effective := header + "http_port_t tcp 8000-8010\nbroken\n"
	local := header + "http_port_t tcp 8005\nbroken\n"
	partial, diagnostics := collectPortInventoryWithRunner(func(_ string, args ...string) ([]byte, error) {
		if args[2] == "-C" {
			return []byte(local), nil
		}
		return []byte(effective), nil
	}, nil)
	if partial.Status != "partial" || partial.LocalClassificationStatus != "partial" || len(diagnostics) != 2 || partial.Mappings[0].Ports[0].Provenance != "unknown" || partial.Mappings[0].Ports[1].Provenance != "custom" || partial.Mappings[0].Ports[2].Provenance != "unknown" {
		t.Fatalf("partial = %#v, diagnostics = %v", partial, diagnostics)
	}
	localUnavailable, _ := collectPortInventoryWithRunner(func(_ string, args ...string) ([]byte, error) {
		if args[2] == "-C" {
			return nil, errors.New("missing semanage")
		}
		return []byte(header + "http_port_t tcp 8080\n"), nil
	}, nil)
	if localUnavailable.Status != "observed" || localUnavailable.LocalClassificationStatus != "unavailable" || localUnavailable.Mappings[0].Ports[0].Provenance != "unknown" {
		t.Fatalf("local unavailable = %#v", localUnavailable)
	}
	unavailable, _ := collectPortInventoryWithRunner(func(string, ...string) ([]byte, error) { return nil, errors.New("missing semanage") }, nil)
	if unavailable.Status != "unavailable" || unavailable.LocalClassificationStatus != "unavailable" || unavailable.Mappings == nil {
		t.Fatalf("unavailable = %#v", unavailable)
	}
	unknown, _ := collectPortInventoryWithRunner(func(string, ...string) ([]byte, error) { return []byte(""), nil }, nil)
	if unknown.Status != "unknown" || unknown.LocalClassificationStatus != "observed" || unknown.Mappings == nil {
		t.Fatalf("unknown = %#v", unknown)
	}
}

func TestLocalPortInventoryTreatsHeaderlessEmptyOutputAsObservedEmpty(t *testing.T) {
	inventory, diagnostics := parseLocalPortInventory("")
	if inventory.Status != "observed" || len(inventory.Mappings) != 0 || len(diagnostics) != 0 {
		t.Fatalf("inventory = %#v, diagnostics = %#v", inventory, diagnostics)
	}
}

func TestPortInventoryParsesHeaderlessSemanageOutput(t *testing.T) {
	inventory, diagnostics := parsePortInventory("http_port_t tcp 80,443\ndns_port_t udp 53\n")
	if inventory.Status != "observed" || len(inventory.Mappings) != 2 || len(diagnostics) != 0 {
		t.Fatalf("inventory = %#v, diagnostics = %#v", inventory, diagnostics)
	}
	if inventory.Mappings[0].Type != "http_port_t" || inventory.Mappings[0].Protocol != "tcp" || inventory.Mappings[0].Ports[0].Start != 80 || inventory.Mappings[0].Ports[1].Start != 443 {
		t.Fatalf("inventory = %#v", inventory)
	}
}

func resolvePortType(mappings []PortMapping, protocol string, port uint16) string {
	for _, mapping := range mappings {
		if mapping.Protocol != protocol {
			continue
		}
		for _, value := range mapping.Ports {
			if port >= value.Start && port <= value.End {
				return mapping.Type
			}
		}
	}
	return ""
}

func resolvePortTypeFromText(output, protocol string, port uint16) string {
	inventory, _ := parsePortInventory(output)
	for _, mapping := range inventory.Mappings {
		if mapping.Protocol != protocol {
			continue
		}
		for _, value := range mapping.Ports {
			if port >= value.Start && port <= value.End {
				return mapping.Type
			}
		}
	}
	return ""
}

func writeFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
