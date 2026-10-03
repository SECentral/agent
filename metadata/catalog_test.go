package metadata

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCollectCatalogIsDeterministicOutsideAcquisitionMetadata(t *testing.T) {
	root := catalogFixtureRoot(t)
	run := catalogRunner(nil)
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }

	first, inspection, err := collectCatalog(root, time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC), run, identity)
	if err != nil || !inspection.Complete() || !inspection.Clean() {
		t.Fatalf("artifact = %#v, inspection = %#v, err = %v", first, inspection, err)
	}
	second, _, err := collectCatalog(root, time.Date(2026, 9, 21, 1, 2, 3, 0, time.UTC), run, identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentDigest != second.ContentDigest || first.Metadata.CollectedAt == second.Metadata.CollectedAt {
		t.Fatalf("digest or metadata changed unexpectedly: %#v %#v", first, second)
	}
	if err := ValidateCatalog(first); err != nil {
		t.Fatal(err)
	}
	if first.Catalog.Families.Booleans.Entries[0] != (CatalogBoolean{Name: "httpd_can_network_connect", Default: false, Description: "Allow network"}) {
		t.Fatalf("booleans = %#v", first.Catalog.Families.Booleans.Entries)
	}
}

func TestCanonicalCatalogGoldenVector(t *testing.T) {
	catalog := DistributionCatalog{
		CollectorSemanticsVersion: 3,
		Policy: CatalogPolicy{
			LoadedPolicyDigest:  "sha256:" + strings.Repeat("a", 64),
			Type:                "targeted",
			KernelPolicyVersion: 33,
			Packages: []PolicyPackage{
				{Name: "selinux-policy-targeted", Epoch: "0", Version: "1", Release: "1", Architecture: "x86_64"},
				{Name: "selinux-policy", Epoch: "0", Version: "1", Release: "2", Architecture: "x86_64"},
			},
		},
		Platform: CatalogPlatform{Distribution: "example", MajorVersion: "9", Architecture: "x86_64"},
		Families: CatalogFamilies{
			Booleans: CatalogBooleans{Complete: true, Entries: []CatalogBoolean{
				{Name: "z_boolean", Default: true, Description: "Z \"quoted\"\n"},
				{Name: "a_boolean", Default: false, Description: "A café boolean"},
			}},
			Ports: CatalogPorts{Complete: true, Mappings: []CatalogPortMapping{
				{Type: "dns_port_t", Protocol: "udp", Start: 53, End: 53},
				{Type: "http_port_t", Protocol: "tcp", Start: 80, End: 81},
			}},
		},
	}
	var vector struct {
		CanonicalJSON string `json:"canonical_json"`
		ContentDigest string `json:"content_digest"`
	}
	data, err := os.ReadFile("testdata/catalog-canonicalization-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	data, err = canonicalCatalogJSON(catalog)
	if err != nil || string(data) != vector.CanonicalJSON {
		t.Fatalf("canonical JSON = %q, err = %v", data, err)
	}
	digest, err := catalogDigest(catalog)
	if err != nil || digest != vector.ContentDigest {
		t.Fatalf("digest = %q, err = %v", digest, err)
	}
}

func TestCanonicalJSONSortsNestedObjects(t *testing.T) {
	first, err := canonicalJSON(map[string]any{"z": nil, "ports": []any{2, 1}, "a": map[string]any{"z": true, "a": false}})
	second, secondErr := canonicalJSON(map[string]any{"a": map[string]any{"a": false, "z": true}, "z": nil, "ports": []any{2, 1}})
	if err != nil || secondErr != nil || string(first) != `{"a":{"a":false,"z":true},"ports":[2,1],"z":null}` || string(first) != string(second) {
		t.Fatalf("canonical JSON = %q %q, errors = %v %v", first, second, err, secondErr)
	}
}

func TestCatalogDigestNormalizesSemanticArrayOrder(t *testing.T) {
	first := testCatalogArtifact(t).Catalog
	second := first
	second.Families.Booleans.Entries = slices.Clone(first.Families.Booleans.Entries)
	second.Families.Ports.Mappings = slices.Clone(first.Families.Ports.Mappings)
	second.Policy.Packages = slices.Clone(first.Policy.Packages)
	for left, right := 0, len(second.Families.Booleans.Entries)-1; left < right; left, right = left+1, right-1 {
		second.Families.Booleans.Entries[left], second.Families.Booleans.Entries[right] = second.Families.Booleans.Entries[right], second.Families.Booleans.Entries[left]
	}
	for left, right := 0, len(second.Families.Ports.Mappings)-1; left < right; left, right = left+1, right-1 {
		second.Families.Ports.Mappings[left], second.Families.Ports.Mappings[right] = second.Families.Ports.Mappings[right], second.Families.Ports.Mappings[left]
	}
	firstDigest, err := catalogDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := catalogDigest(second)
	if err != nil || firstDigest != secondDigest {
		t.Fatalf("digests = %q %q, err = %v", firstDigest, secondDigest, err)
	}
}

func TestCatalogDigestChangesForSemanticContent(t *testing.T) {
	first := testCatalogArtifact(t).Catalog
	second := first
	second.Families.Booleans.Entries = slices.Clone(first.Families.Booleans.Entries)
	second.Families.Booleans.Entries[0].Description = "different"
	firstDigest, err := catalogDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := catalogDigest(second)
	if err != nil || firstDigest == secondDigest {
		t.Fatalf("digests = %q %q, err = %v", firstDigest, secondDigest, err)
	}
}

func TestCollectCatalogReportsLocalCustomizationsBeforeRefusing(t *testing.T) {
	root := catalogFixtureRoot(t)
	run := catalogRunner(map[string][]byte{
		"semanage boolean -l -C":  []byte("SELinux boolean State Default\nhttpd_can_network_connect (on , off) Allow network\n"),
		"semanage port -l -C -n":  []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 8443\n"),
		"semanage fcontext -l -C": []byte("SELinux fcontext type Context\n/srv/www(/.*)? all files system_u:object_r:httpd_sys_content_t:s0\n"),
	})
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }

	_, inspection, err := collectCatalog(root, time.Now(), run, identity)
	if err == nil || !strings.Contains(err.Error(), "local SELinux customization") {
		t.Fatalf("err = %v", err)
	}
	if !inspection.Complete() || inspection.Clean() || len(inspection.LocalBooleans) != 1 || len(inspection.LocalPorts) != 1 || len(inspection.LocalFileContexts) != 1 {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestCollectCatalogRefusesIncompleteCustomizationInspection(t *testing.T) {
	root := catalogFixtureRoot(t)
	base := catalogRunner(nil)
	run := func(name string, args ...string) ([]byte, error) {
		if name == "semanage" && strings.Join(args, " ") == "fcontext -l -C" {
			return nil, errors.New("not installed")
		}
		return base(name, args...)
	}
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }

	_, inspection, err := collectCatalog(root, time.Now(), run, identity)
	if err == nil || !strings.Contains(err.Error(), "inspection incomplete") {
		t.Fatalf("err = %v", err)
	}
	if inspection.Complete() || !inspection.Clean() || len(inspection.Diagnostics) != 1 {
		t.Fatalf("inspection = %#v", inspection)
	}
}

func TestCollectCatalogRefusesIncompleteBooleanAndPortInventories(t *testing.T) {
	root := catalogFixtureRoot(t)
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }
	for name, overrides := range map[string]map[string][]byte{
		"boolean": {"getsebool -a": []byte("httpd_can_network_connect --> off\nbroken\n")},
		"port":    {"semanage port -l -n": []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 80\nbroken\n")},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := collectCatalog(root, time.Now(), catalogRunner(overrides), identity)
			if err == nil || !strings.Contains(err.Error(), "incomplete") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestValidateCatalogRejectsStructuralAndDigestFailures(t *testing.T) {
	for name, mutate := range map[string]func(*CatalogArtifact){
		"duplicate boolean": func(artifact *CatalogArtifact) {
			artifact.Catalog.Families.Booleans.Entries = append(artifact.Catalog.Families.Booleans.Entries, artifact.Catalog.Families.Booleans.Entries[0])
			setCatalogDigest(t, artifact)
		},
		"duplicate port": func(artifact *CatalogArtifact) {
			ports := artifact.Catalog.Families.Ports.Mappings
			artifact.Catalog.Families.Ports.Mappings = append([]CatalogPortMapping{ports[0], ports[0]}, ports[1:]...)
			setCatalogDigest(t, artifact)
		},
		"modified content": func(artifact *CatalogArtifact) {
			artifact.Catalog.Families.Booleans.Entries[0].Description = "modified"
		},
		"invalid policy digest": func(artifact *CatalogArtifact) {
			artifact.Catalog.Policy.LoadedPolicyDigest = "sha256:not-a-digest"
			setCatalogDigest(t, artifact)
		},
		"invalid port protocol": func(artifact *CatalogArtifact) {
			artifact.Catalog.Families.Ports.Mappings[0].Protocol = "icmp"
			setCatalogDigest(t, artifact)
		},
		"noncanonical booleans": func(artifact *CatalogArtifact) {
			artifact.Catalog.Families.Booleans.Entries = append(artifact.Catalog.Families.Booleans.Entries, CatalogBoolean{Name: "aaa", Default: false})
			setCatalogDigest(t, artifact)
		},
		"noncanonical ports": func(artifact *CatalogArtifact) {
			artifact.Catalog.Families.Ports.Mappings = append(artifact.Catalog.Families.Ports.Mappings, CatalogPortMapping{Type: "dns_port_t", Protocol: "udp", Start: 53, End: 53})
			artifact.Catalog.Families.Ports.Mappings[0], artifact.Catalog.Families.Ports.Mappings[1] = artifact.Catalog.Families.Ports.Mappings[1], artifact.Catalog.Families.Ports.Mappings[0]
			setCatalogDigest(t, artifact)
		},
		"duplicate policy package": func(artifact *CatalogArtifact) {
			artifact.Catalog.Policy.Packages = append(artifact.Catalog.Policy.Packages, artifact.Catalog.Policy.Packages[0])
			setCatalogDigest(t, artifact)
		},
	} {
		t.Run(name, func(t *testing.T) {
			artifact := testCatalogArtifact(t)
			mutate(&artifact)
			if err := ValidateCatalog(artifact); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestValidateCatalogAcceptsSemanagePortProtocols(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "sctp", "dccp"} {
		t.Run(protocol, func(t *testing.T) {
			artifact := testCatalogArtifact(t)
			artifact.Catalog.Families.Ports.Mappings = []CatalogPortMapping{{Type: "test_port_t", Protocol: protocol, Start: 1234, End: 1234}}
			setCatalogDigest(t, &artifact)
			if err := ValidateCatalog(artifact); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCollectionCanonicalizesEquivalentToolOutputOrder(t *testing.T) {
	root := catalogFixtureRoot(t)
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }
	first, _, err := collectCatalog(root, time.Now(), catalogRunner(map[string][]byte{
		"getsebool -a":        []byte("httpd_can_network_connect --> off\nvirt_use_nfs --> off\n"),
		"semanage boolean -l": []byte("SELinux boolean State Default\nhttpd_can_network_connect (off , off) Allow network\nvirt_use_nfs (off , off) Allow NFS\n"),
		"semanage port -l -n": []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 80,443\n"),
	}), identity)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := collectCatalog(root, time.Now(), catalogRunner(map[string][]byte{
		"getsebool -a":        []byte("virt_use_nfs --> off\nhttpd_can_network_connect --> off\n"),
		"semanage boolean -l": []byte("SELinux boolean State Default\nvirt_use_nfs (off , off) Allow NFS\nhttpd_can_network_connect (off , off) Allow network\n"),
		"semanage port -l -n": []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 443,80\n"),
	}), identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContentDigest != second.ContentDigest {
		t.Fatalf("digests differ: %s %s", first.ContentDigest, second.ContentDigest)
	}
}

func TestCatalogCommandEnvForcesCLocale(t *testing.T) {
	environment := catalogCommandEnv([]string{"LANG=fr_FR.UTF-8", "LC_ALL=fr_FR.UTF-8", "LANGUAGE=fr", "PATH=/usr/bin"})
	if strings.Join(environment, "\n") != "PATH=/usr/bin\nLC_ALL=C\nLANG=C\nLANGUAGE=C" {
		t.Fatalf("environment = %#v", environment)
	}
}

func TestCatalogAndAgentBooleanInventoryAgree(t *testing.T) {
	run := catalogRunner(map[string][]byte{
		"getsebool -a":        []byte("virt_use_nfs --> on\nhttpd_can_network_connect --> off\n"),
		"semanage boolean -l": []byte("SELinux boolean State Default\nvirt_use_nfs (on , off) Allow NFS\nhttpd_can_network_connect (off , off) Allow network\n"),
	})
	status, observed, diagnostics := collectBooleanInventoryWithRunner(run, nil)
	catalog, err := catalogBooleans(run)
	if err != nil || status != "observed" || len(diagnostics) != 0 {
		t.Fatalf("catalog = %#v, status = %q, diagnostics = %v, err = %v", catalog, status, diagnostics, err)
	}
	if len(observed) != len(catalog.Entries) {
		t.Fatalf("observed = %#v, catalog = %#v", observed, catalog)
	}
	for index, boolean := range observed {
		entry := catalog.Entries[index]
		if boolean.Name != entry.Name || boolean.Default == nil || *boolean.Default != entry.Default || boolean.Description != entry.Description {
			t.Fatalf("observed = %#v, catalog = %#v", boolean, entry)
		}
	}
}

func TestCatalogAndAgentPortInventoryAgree(t *testing.T) {
	run := catalogRunner(map[string][]byte{
		"semanage port -l -n":    []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 443,80-81,8443\ndns_port_t udp 53\n"),
		"semanage port -l -C -n": []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 8443\n"),
	})
	observed, diagnostics := collectPortInventoryWithRunner(run, nil)
	inspection, err := inspectCatalogSource(run)
	if err != nil || len(diagnostics) != 0 || observed.Status != "observed" || observed.LocalClassificationStatus != "observed" {
		t.Fatalf("inspection = %#v, observed = %#v, diagnostics = %v, err = %v", inspection, observed, diagnostics, err)
	}
	if inspection.Clean() || len(inspection.LocalPorts) != 1 || inspection.LocalPorts[0] != (CatalogPortMapping{Type: "http_port_t", Protocol: "tcp", Start: 8443, End: 8443}) {
		t.Fatalf("inspection = %#v", inspection)
	}
	if got, want := flattenPorts(observed.Mappings), []CatalogPortMapping{
		{Type: "http_port_t", Protocol: "tcp", Start: 80, End: 81},
		{Type: "http_port_t", Protocol: "tcp", Start: 443, End: 443},
		{Type: "http_port_t", Protocol: "tcp", Start: 8443, End: 8443},
		{Type: "dns_port_t", Protocol: "udp", Start: 53, End: 53},
	}; !equalCatalogPorts(got, want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
}

func TestCatalogInspectionAndAgentBooleanValuesAgreeOnLocalChange(t *testing.T) {
	run := catalogRunner(map[string][]byte{
		"getsebool -a":           []byte("httpd_can_network_connect --> on\n"),
		"semanage boolean -l":    []byte("SELinux boolean State Default\nhttpd_can_network_connect (on , off) Allow network\n"),
		"semanage boolean -l -C": []byte("SELinux boolean State Default\nhttpd_can_network_connect (on , off) Allow network\n"),
	})
	_, observed, diagnostics := collectBooleanInventoryWithRunner(run, nil)
	inspection, err := inspectCatalogSource(run)
	if err != nil || len(diagnostics) != 0 || inspection.Clean() || len(inspection.LocalBooleans) != 1 || inspection.LocalBooleans[0] != observed[0].Name || observed[0].Current == nil || !*observed[0].Current || observed[0].Default == nil || *observed[0].Default {
		t.Fatalf("inspection = %#v, observed = %#v, diagnostics = %v, err = %v", inspection, observed, diagnostics, err)
	}
}

func testCatalogArtifact(t *testing.T) CatalogArtifact {
	t.Helper()
	identity := func([]error) (string, []error) { return "sha256:" + strings.Repeat("a", 64), nil }
	artifact, _, err := collectCatalog(catalogFixtureRoot(t), time.Now(), catalogRunner(nil), identity)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func setCatalogDigest(t *testing.T, artifact *CatalogArtifact) {
	t.Helper()
	digest, err := catalogDigest(artifact.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	artifact.ContentDigest = digest
}

func TestCollectCatalogRejectsPolicyChangeDuringCollection(t *testing.T) {
	root := catalogFixtureRoot(t)
	identityCalls := 0
	identity := func([]error) (string, []error) {
		identityCalls++
		if identityCalls == 1 {
			return "sha256:" + strings.Repeat("a", 64), nil
		}
		return "sha256:" + strings.Repeat("b", 64), nil
	}

	_, _, err := collectCatalog(root, time.Now(), catalogRunner(nil), identity)
	if err == nil || !strings.Contains(err.Error(), "changed during collection") {
		t.Fatalf("err = %v", err)
	}
}

func catalogFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "/etc/os-release", "ID=almalinux\nVERSION_ID=9.5\n")
	writeFixture(t, root, "/etc/selinux/config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
	writeFixture(t, root, "/sys/fs/selinux/enforce", "1\n")
	writeFixture(t, root, "/sys/fs/selinux/policyvers", "33\n")
	return root
}

func catalogRunner(overrides map[string][]byte) func(string, ...string) ([]byte, error) {
	return func(name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		if value, ok := overrides[key]; ok {
			return value, nil
		}
		switch key {
		case "semanage boolean -l":
			return []byte("SELinux boolean State Default\nhttpd_can_network_connect (off , off) Allow network\n"), nil
		case "semanage boolean -l -C":
			return []byte("SELinux boolean State Default\n"), nil
		case "semanage port -l -n":
			return []byte("SELinux Port Type Proto Port Number\nhttp_port_t tcp 80,443\n"), nil
		case "semanage port -l -C -n":
			return []byte("SELinux Port Type Proto Port Number\n"), nil
		case "semanage fcontext -l -C":
			return []byte("SELinux fcontext type Context\n"), nil
		case "getsebool -a":
			return []byte("httpd_can_network_connect --> off\n"), nil
		case "uname -m":
			return []byte("x86_64\n"), nil
		case "rpm -q --qf %{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n selinux-policy-targeted":
			return []byte("selinux-policy-targeted\t0\t38.1\t1.el9\tx86_64\n"), nil
		}
		return nil, errors.New("unexpected command: " + key)
	}
}
