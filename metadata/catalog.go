package metadata

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	CatalogSchemaVersion             = 1
	CatalogCollectorSemanticsVersion = 3
	CatalogCollectorVersion          = "secentral-catalog-collector-v1"
)

type CatalogArtifact struct {
	SchemaVersion int                 `json:"schema_version"`
	ContentDigest string              `json:"content_digest"`
	Catalog       DistributionCatalog `json:"catalog"`
	Metadata      CatalogMetadata     `json:"metadata"`
}

type DistributionCatalog struct {
	CollectorSemanticsVersion int             `json:"collector_semantics_version"`
	Policy                    CatalogPolicy   `json:"policy"`
	Platform                  CatalogPlatform `json:"platform"`
	Families                  CatalogFamilies `json:"families"`
}

type CatalogPolicy struct {
	LoadedPolicyDigest  string          `json:"loaded_policy_digest"`
	Type                string          `json:"type"`
	KernelPolicyVersion int             `json:"kernel_policy_version"`
	Packages            []PolicyPackage `json:"packages"`
}

type CatalogPlatform struct {
	Distribution string `json:"distribution"`
	MajorVersion string `json:"major_version"`
	Architecture string `json:"architecture"`
}

type CatalogFamilies struct {
	Booleans CatalogBooleans `json:"booleans"`
	Ports    CatalogPorts    `json:"ports"`
}

type CatalogBooleans struct {
	Complete bool             `json:"complete"`
	Entries  []CatalogBoolean `json:"entries"`
}

type CatalogBoolean struct {
	Name        string `json:"name"`
	Default     bool   `json:"default"`
	Description string `json:"description,omitempty"`
}

type CatalogPorts struct {
	Complete bool                 `json:"complete"`
	Mappings []CatalogPortMapping `json:"mappings"`
}

type CatalogPortMapping struct {
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	Start    uint16 `json:"start"`
	End      uint16 `json:"end"`
}

type CatalogMetadata struct {
	CollectedAt      time.Time `json:"collected_at"`
	CollectorVersion string    `json:"collector_version"`
}

type CatalogInspection struct {
	LocalBooleans     []string             `json:"local_booleans"`
	LocalPorts        []CatalogPortMapping `json:"local_ports"`
	LocalFileContexts []FileContextMapping `json:"local_file_contexts"`
	Diagnostics       []string             `json:"diagnostics,omitempty"`
}

// Complete reports whether the limited local semanage inspection succeeded.
// It does not establish that the loaded policy is untouched distribution policy.
func (i CatalogInspection) Complete() bool {
	return len(i.Diagnostics) == 0
}

func (i CatalogInspection) Clean() bool {
	return len(i.LocalBooleans) == 0 && len(i.LocalPorts) == 0 && len(i.LocalFileContexts) == 0
}

func CollectCatalog() (CatalogArtifact, CatalogInspection, error) {
	return collectCatalog("/", time.Now().UTC(), commandOutput, collectPolicyIdentity)
}

func InspectCatalogSource() (CatalogInspection, error) {
	return inspectCatalogSource(commandOutput)
}

func collectCatalog(root string, now time.Time, run func(string, ...string) ([]byte, error), policyIdentity func([]error) (string, []error)) (CatalogArtifact, CatalogInspection, error) {
	inspection, err := inspectCatalogSource(run)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	if !inspection.Complete() {
		return CatalogArtifact{}, inspection, errors.New("catalog generation refused: local customization inspection incomplete")
	}
	if !inspection.Clean() {
		return CatalogArtifact{}, inspection, errors.New("catalog generation refused: local SELinux customization detected")
	}

	before, diagnostics := policyIdentity(nil)
	if len(diagnostics) > 0 {
		return CatalogArtifact{}, inspection, fmt.Errorf("loaded policy identity: %w", errors.Join(diagnostics...))
	}
	if before == "" {
		return CatalogArtifact{}, inspection, errors.New("loaded policy identity unavailable")
	}
	platform, err := catalogPlatform(root, run)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	policy, err := catalogPolicy(root, run, before)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	booleans, err := catalogBooleans(run)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	ports, err := catalogPorts(run)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	after, diagnostics := policyIdentity(nil)
	if len(diagnostics) > 0 {
		return CatalogArtifact{}, inspection, fmt.Errorf("loaded policy identity after collection: %w", errors.Join(diagnostics...))
	}
	if after == "" {
		return CatalogArtifact{}, inspection, errors.New("loaded policy identity after collection unavailable")
	}
	if before != after {
		return CatalogArtifact{}, inspection, errors.New("catalog generation refused: loaded policy changed during collection")
	}

	artifact := CatalogArtifact{
		SchemaVersion: CatalogSchemaVersion,
		Catalog: DistributionCatalog{
			CollectorSemanticsVersion: CatalogCollectorSemanticsVersion,
			Policy:                    policy,
			Platform:                  platform,
			Families:                  CatalogFamilies{Booleans: booleans, Ports: ports},
		},
		Metadata: CatalogMetadata{CollectedAt: now.UTC(), CollectorVersion: CatalogCollectorVersion},
	}
	digest, err := catalogDigest(artifact.Catalog)
	if err != nil {
		return CatalogArtifact{}, inspection, err
	}
	artifact.ContentDigest = digest
	return artifact, inspection, ValidateCatalog(artifact)
}

func inspectCatalogSource(run func(string, ...string) ([]byte, error)) (CatalogInspection, error) {
	var result CatalogInspection
	booleanOutput, booleanErr := run("semanage", "boolean", "-l", "-C")
	if booleanErr != nil {
		result.Diagnostics = append(result.Diagnostics, "local boolean inspection unavailable")
	} else {
		booleans, diagnostics := parsePersistentBooleans(string(booleanOutput))
		if len(diagnostics) > 0 {
			result.Diagnostics = append(result.Diagnostics, "local boolean inspection incomplete")
		}
		result.LocalBooleans = slices.Sorted(maps.Keys(booleans))
	}
	portOutput, portErr := run("semanage", "port", "-l", "-C", "-n")
	if portErr != nil {
		result.Diagnostics = append(result.Diagnostics, "local port inspection unavailable")
	} else {
		inventory, diagnostics := parseLocalPortInventory(string(portOutput))
		if inventory.Status != "observed" || len(diagnostics) > 0 {
			result.Diagnostics = append(result.Diagnostics, "local port inspection incomplete")
		}
		result.LocalPorts = flattenPortMappings(inventory.Mappings)
	}
	fileContextOutput, fileContextErr := run("semanage", "fcontext", "-l", "-C")
	if fileContextErr != nil {
		result.Diagnostics = append(result.Diagnostics, "local file-context inspection unavailable")
	} else {
		contexts, diagnostics := parseFileContexts(string(fileContextOutput), nil)
		if len(diagnostics) > 0 {
			result.Diagnostics = append(result.Diagnostics, "local file-context inspection incomplete")
		}
		result.LocalFileContexts = contexts
	}
	return result, nil
}

func catalogPlatform(root string, run func(string, ...string) ([]byte, error)) (CatalogPlatform, error) {
	osRelease, err := read(root, "/etc/os-release")
	if err != nil {
		return CatalogPlatform{}, fmt.Errorf("os release: %w", err)
	}
	id, version, err := parseOSRelease(osRelease)
	if err != nil {
		return CatalogPlatform{}, fmt.Errorf("os release: %w", err)
	}
	if id == "" || version == "" {
		return CatalogPlatform{}, errors.New("os release incomplete")
	}
	architecture, err := run("uname", "-m")
	if err != nil || strings.TrimSpace(string(architecture)) == "" {
		return CatalogPlatform{}, errors.New("architecture unavailable")
	}
	major, _, _ := strings.Cut(version, ".")
	return CatalogPlatform{Distribution: id, MajorVersion: major, Architecture: strings.TrimSpace(string(architecture))}, nil
}

func catalogPolicy(root string, run func(string, ...string) ([]byte, error), identity string) (CatalogPolicy, error) {
	metadata, diagnostics := collectSELinux(root, nil)
	if len(diagnostics) > 0 {
		return CatalogPolicy{}, fmt.Errorf("policy metadata unavailable: %w", errors.Join(diagnostics...))
	}
	if !metadata.Enabled || metadata.ConfiguredPolicyType == nil || metadata.KernelPolicyVersion == nil {
		return CatalogPolicy{}, errors.New("policy metadata incomplete")
	}
	packageOutput, err := run("rpm", "-q", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", "selinux-policy-targeted")
	if err != nil {
		packageOutput, err = run("rpm", "-q", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", "selinux-policy")
	}
	if err != nil {
		return CatalogPolicy{}, errors.New("policy package unavailable")
	}
	fields := strings.Split(strings.TrimSpace(string(packageOutput)), "\t")
	if len(fields) != 5 || fields[0] == "" || fields[2] == "" || fields[3] == "" || fields[4] == "" {
		return CatalogPolicy{}, errors.New("policy package output malformed")
	}
	return CatalogPolicy{LoadedPolicyDigest: identity, Type: *metadata.ConfiguredPolicyType, KernelPolicyVersion: *metadata.KernelPolicyVersion, Packages: []PolicyPackage{{Name: fields[0], Epoch: fields[1], Version: fields[2], Release: fields[3], Architecture: fields[4]}}}, nil
}

func catalogBooleans(run func(string, ...string) ([]byte, error)) (CatalogBooleans, error) {
	status, values, diagnostics := collectBooleanInventoryWithRunner(run, nil)
	if status != "observed" || len(diagnostics) > 0 {
		return CatalogBooleans{}, errors.New("boolean inventory incomplete")
	}
	entries := make([]CatalogBoolean, 0, len(values))
	for _, value := range values {
		if value.Status != "observed" || value.Default == nil {
			return CatalogBooleans{}, errors.New("boolean default unavailable")
		}
		entries = append(entries, CatalogBoolean{Name: value.Name, Default: *value.Default, Description: value.Description})
	}
	return CatalogBooleans{Complete: true, Entries: entries}, nil
}

func catalogPorts(run func(string, ...string) ([]byte, error)) (CatalogPorts, error) {
	inventory, diagnostics := collectPortInventoryWithRunner(run, nil)
	if inventory.Status != "observed" || inventory.LocalClassificationStatus != "observed" || len(diagnostics) > 0 {
		return CatalogPorts{}, errors.New("port inventory incomplete")
	}
	return CatalogPorts{Complete: true, Mappings: flattenPorts(inventory.Mappings)}, nil
}

func flattenPortMappings(mappings []parsedPortMapping) []CatalogPortMapping {
	result := make([]CatalogPortMapping, 0)
	for _, mapping := range mappings {
		for _, port := range mapping.Ports {
			result = append(result, CatalogPortMapping{Type: mapping.Type, Protocol: mapping.Protocol, Start: port.Start, End: port.End})
		}
	}
	sortCatalogPorts(result)
	return result
}

func flattenPorts(mappings []PortMapping) []CatalogPortMapping {
	result := make([]CatalogPortMapping, 0)
	for _, mapping := range mappings {
		for _, port := range mapping.Ports {
			result = append(result, CatalogPortMapping{Type: mapping.Type, Protocol: mapping.Protocol, Start: port.Start, End: port.End})
		}
	}
	sortCatalogPorts(result)
	return result
}

func sortCatalogPorts(values []CatalogPortMapping) {
	slices.SortFunc(values, func(a, b CatalogPortMapping) int {
		if order := cmp.Compare(a.Protocol, b.Protocol); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Start, b.Start); order != 0 {
			return order
		}
		if order := cmp.Compare(a.End, b.End); order != 0 {
			return order
		}
		return cmp.Compare(a.Type, b.Type)
	})
}

func catalogDigest(catalog DistributionCatalog) (string, error) {
	data, err := canonicalCatalogJSON(catalog)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateCatalog(artifact CatalogArtifact) error {
	if artifact.SchemaVersion != CatalogSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", artifact.SchemaVersion)
	}
	if artifact.Catalog.CollectorSemanticsVersion != CatalogCollectorSemanticsVersion {
		return fmt.Errorf("unsupported collector semantics version %d", artifact.Catalog.CollectorSemanticsVersion)
	}
	if !validSHA256(artifact.Catalog.Policy.LoadedPolicyDigest) {
		return errors.New("invalid loaded policy digest")
	}
	if artifact.Catalog.Platform.Distribution == "" || artifact.Catalog.Platform.MajorVersion == "" || artifact.Catalog.Platform.Architecture == "" || artifact.Catalog.Policy.Type == "" || artifact.Catalog.Policy.KernelPolicyVersion == 0 || len(artifact.Catalog.Policy.Packages) == 0 {
		return errors.New("catalog identity incomplete")
	}
	if artifact.Metadata.CollectedAt.IsZero() || artifact.Metadata.CollectorVersion == "" {
		return errors.New("catalog acquisition metadata incomplete")
	}
	for _, pkg := range artifact.Catalog.Policy.Packages {
		if pkg.Name == "" || pkg.Version == "" || pkg.Release == "" || pkg.Architecture == "" {
			return errors.New("policy package identity incomplete")
		}
	}
	packages := slices.Clone(artifact.Catalog.Policy.Packages)
	sortCatalogPackages(packages)
	if !equalCatalogPackages(packages, artifact.Catalog.Policy.Packages) {
		return errors.New("policy packages are not canonical")
	}
	for index := 1; index < len(artifact.Catalog.Policy.Packages); index++ {
		if artifact.Catalog.Policy.Packages[index-1] == artifact.Catalog.Policy.Packages[index] {
			return errors.New("policy packages invalid")
		}
	}
	if !artifact.Catalog.Families.Booleans.Complete || !artifact.Catalog.Families.Ports.Complete {
		return errors.New("required catalog family incomplete")
	}
	if !slices.IsSortedFunc(artifact.Catalog.Families.Booleans.Entries, func(a, b CatalogBoolean) int {
		return cmp.Compare(a.Name, b.Name)
	}) {
		return errors.New("boolean entries are not canonical")
	}
	for index, entry := range artifact.Catalog.Families.Booleans.Entries {
		if entry.Name == "" || index > 0 && artifact.Catalog.Families.Booleans.Entries[index-1].Name == entry.Name {
			return errors.New("boolean entries invalid")
		}
	}
	ports := slices.Clone(artifact.Catalog.Families.Ports.Mappings)
	sortCatalogPorts(ports)
	if !equalCatalogPorts(ports, artifact.Catalog.Families.Ports.Mappings) {
		return errors.New("port mappings are not canonical")
	}
	for index, mapping := range artifact.Catalog.Families.Ports.Mappings {
		if mapping.Type == "" || !validPortProtocol(mapping.Protocol) || mapping.End < mapping.Start || index > 0 && artifact.Catalog.Families.Ports.Mappings[index-1] == mapping {
			return errors.New("port mappings invalid")
		}
	}
	digest, err := catalogDigest(artifact.Catalog)
	if err != nil {
		return err
	}
	if artifact.ContentDigest != digest {
		return errors.New("content digest mismatch")
	}
	return nil
}

func validPortProtocol(protocol string) bool {
	return protocol == "tcp" || protocol == "udp" || protocol == "sctp" || protocol == "dccp"
}

func validSHA256(value string) bool {
	digest, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil && strings.ToLower(value) == value
}

func equalCatalogPorts(left, right []CatalogPortMapping) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func commandOutput(name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Env = catalogCommandEnv(os.Environ())
	return command.Output()
}

func catalogCommandEnv(environment []string) []string {
	result := make([]string, 0, len(environment)+3)
	for _, value := range environment {
		key, _, _ := strings.Cut(value, "=")
		if key != "LC_ALL" && key != "LANG" && key != "LANGUAGE" {
			result = append(result, value)
		}
	}
	return append(result, "LC_ALL=C", "LANG=C", "LANGUAGE=C")
}
