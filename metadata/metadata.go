package metadata

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type HostMetadata struct {
	ID       string           `json:"id,omitempty"`
	Hostname string           `json:"hostname,omitempty"`
	BootID   string           `json:"boot_id,omitempty"`
	Platform PlatformMetadata `json:"platform"`
	SELinux  SELinuxMetadata  `json:"selinux"`
}

type PlatformMetadata struct {
	OSID      string `json:"os_id,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Kernel    string `json:"kernel_release,omitempty"`
	Arch      string `json:"architecture,omitempty"`
}

type EnforcementMode string

const (
	Enforcing  EnforcementMode = "enforcing"
	Permissive EnforcementMode = "permissive"
	Disabled   EnforcementMode = "disabled"
	Unknown    EnforcementMode = "unknown"
)

type SELinuxMetadata struct {
	Enabled              bool             `json:"enabled"`
	Enforcement          EnforcementMode  `json:"enforcement"`
	ConfiguredPolicyType *string          `json:"configured_policy_type,omitempty"`
	KernelPolicyVersion  *int             `json:"kernel_policy_version,omitempty"`
	PolicyIdentity       string           `json:"policy_identity,omitempty"`
	Policy               PolicyMetadata   `json:"policy"`
	BooleanStatus        string           `json:"boolean_status,omitempty"`
	Booleans             []SELinuxBoolean `json:"booleans,omitempty"`
}

type SELinuxBoolean struct {
	Name        string `json:"name"`
	Current     *bool  `json:"current"`
	Default     *bool  `json:"default"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"`
}

type PolicyMetadata struct {
	Package                   *PolicyPackage           `json:"package,omitempty"`
	Modules                   []PolicyModule           `json:"modules,omitempty"`
	FileContexts              []FileContextMapping     `json:"file_contexts"`
	FileContextMappingsStatus string                   `json:"file_context_mappings_status,omitempty"`
	LocalFileContextMappings  []FileContextMapping     `json:"local_file_context_mappings"`
	FileContextEquivalences   []FileContextEquivalence `json:"file_context_equivalences"`
	PortInventory             *PortInventory           `json:"port_inventory,omitempty"`
	// CustomModules is retained for protocol compatibility with older agents.
	CustomModules []PolicyModule `json:"custom_modules,omitempty"`
}

type PortInventory struct {
	Status                    string        `json:"status"`
	Mappings                  []PortMapping `json:"mappings"`
	LocalClassificationStatus string        `json:"local_classification_status"`
}

type PortMapping struct {
	Type     string      `json:"type"`
	Protocol string      `json:"protocol"`
	Ports    []PortRange `json:"ports"`
}

type PortRange struct {
	Start      uint16 `json:"start"`
	End        uint16 `json:"end"`
	Provenance string `json:"provenance"`
}

type PolicyPackage struct {
	Name         string `json:"name"`
	Epoch        string `json:"epoch,omitempty"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
}

type PolicyModule struct {
	Name          string `json:"name"`
	Priority      int    `json:"priority,omitempty"`
	Version       string `json:"version,omitempty"`
	Checksum      string `json:"checksum,omitempty"`
	Provenance    string `json:"provenance"`
	SourcePackage string `json:"source_package,omitempty"`
}

type FileContextMapping struct {
	Pattern    string `json:"pattern"`
	FileType   string `json:"file_type,omitempty"`
	Context    string `json:"context"`
	Provenance string `json:"provenance"`
}

type FileContextEquivalence struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Provenance string `json:"provenance"`
}

// Collect returns a point-in-time snapshot. root is normally "/" and exists
// as an argument so tests can use a fixture filesystem.
func Collect(root string) (HostMetadata, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return collect(root, hostname, kernelRelease)
}

// CollectIdentity reads only the host and boot identifiers needed to spool
// audit evidence before a full SELinux state checkpoint is available.
func CollectIdentity(root string) (HostMetadata, error) {
	hostname, _ := os.Hostname()
	metadata := HostMetadata{Hostname: hostname, Platform: PlatformMetadata{Arch: runtime.GOARCH}}
	var diagnostics []error
	if value, err := read(root, "/etc/machine-id"); err == nil {
		metadata.ID = hostID(value)
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("machine id: %w", err))
	}
	if value, err := read(root, "/proc/sys/kernel/random/boot_id"); err == nil {
		metadata.BootID = strings.TrimSpace(value)
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("boot id: %w", err))
	}
	return metadata, errors.Join(diagnostics...)
}

func collect(root, hostname string, kernel func() (string, error)) (HostMetadata, error) {
	var diagnostics []error
	metadata := HostMetadata{Hostname: hostname, Platform: PlatformMetadata{Arch: runtime.GOARCH}}

	if value, err := read(root, "/etc/machine-id"); err == nil {
		metadata.ID = hostID(value)
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("machine id: %w", err))
	}
	if value, err := read(root, "/proc/sys/kernel/random/boot_id"); err == nil {
		metadata.BootID = strings.TrimSpace(value)
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("boot id: %w", err))
	}
	if value, err := kernel(); err == nil {
		metadata.Platform.Kernel = value
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("kernel release: %w", err))
	}
	if value, err := read(root, "/etc/os-release"); err == nil {
		osID, osVersion, parseErr := parseOSRelease(value)
		metadata.Platform.OSID, metadata.Platform.OSVersion = osID, osVersion
		if parseErr != nil {
			diagnostics = append(diagnostics, parseErr)
		}
	} else {
		diagnostics = append(diagnostics, fmt.Errorf("os release: %w", err))
	}

	metadata.SELinux, diagnostics = collectSELinux(root, diagnostics)
	if root == "/" {
		metadata.SELinux.Policy, diagnostics = collectPolicyMetadata(diagnostics)
		metadata.SELinux.PolicyIdentity, diagnostics = collectPolicyIdentity(diagnostics)
		metadata.SELinux.BooleanStatus, metadata.SELinux.Booleans, diagnostics = collectBooleanInventory(diagnostics)
	}
	return metadata, errors.Join(diagnostics...)
}

func collectPolicyIdentity(diagnostics []error) (string, []error) {
	_, identity, err := ReadPolicyArtifact("/")
	if err != nil {
		return "", append(diagnostics, fmt.Errorf("policy identity: %w", err))
	}
	return identity, diagnostics
}

func ReadPolicyArtifact(root string) ([]byte, string, error) {
	artifact, err := os.ReadFile(filepath.Join(root, "sys/fs/selinux/policy"))
	if err != nil {
		return nil, "", err
	}
	if len(artifact) == 0 {
		return nil, "", errors.New("loaded policy is empty")
	}
	digest := sha256.Sum256(artifact)
	return artifact, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func collectBooleanInventory(diagnostics []error) (string, []SELinuxBoolean, []error) {
	return collectBooleanInventoryWithRunner(func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}, diagnostics)
}

func collectBooleanInventoryWithRunner(run func(string, ...string) ([]byte, error), diagnostics []error) (string, []SELinuxBoolean, []error) {
	currentOutput, currentErr := run("getsebool", "-a")
	defaultOutput, defaultErr := run("semanage", "boolean", "-l")
	if currentErr != nil && defaultErr != nil {
		return "unavailable", nil, append(diagnostics, errors.New("selinux booleans: tooling unavailable"))
	}
	if currentErr != nil {
		diagnostics = append(diagnostics, errors.New("selinux booleans: current values unavailable"))
	}
	if defaultErr != nil {
		diagnostics = append(diagnostics, errors.New("selinux booleans: semanage reported defaults unavailable"))
	}

	current, currentDiagnostics := parseCurrentBooleans(string(currentOutput))
	defaults, defaultDiagnostics := parsePersistentBooleans(string(defaultOutput))
	diagnostics = append(diagnostics, currentDiagnostics...)
	diagnostics = append(diagnostics, defaultDiagnostics...)
	values := make(map[string]*SELinuxBoolean)
	for name, value := range current {
		values[name] = &SELinuxBoolean{Name: name, Current: new(value), Status: "observed"}
	}
	for name, value := range defaults {
		entry := values[name]
		if entry == nil {
			entry = &SELinuxBoolean{Name: name, Status: "observed"}
			values[name] = entry
		}
		entry.Default = new(value.Value)
		entry.Description = value.Description
	}
	result := make([]SELinuxBoolean, 0, len(values))
	for _, value := range values {
		if value.Current == nil || value.Default == nil {
			value.Status = "unknown"
		}
		result = append(result, *value)
	}
	slices.SortFunc(result, func(a, b SELinuxBoolean) int { return cmp.Compare(a.Name, b.Name) })
	if len(result) == 0 {
		return "unknown", result, diagnostics
	}
	return "observed", result, diagnostics
}

func parseCurrentBooleans(output string) (map[string]bool, []error) {
	values := make(map[string]bool)
	var diagnostics []error
	for lineNumber, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || fields[1] != "-->" || (fields[2] != "on" && fields[2] != "off") {
			diagnostics = append(diagnostics, fmt.Errorf("getsebool line %d: malformed output", lineNumber+1))
			continue
		}
		values[fields[0]] = fields[2] == "on"
	}
	return values, diagnostics
}

type persistentBoolean struct {
	Value       bool
	Description string
}

func parsePersistentBooleans(output string) (map[string]persistentBoolean, []error) {
	values := make(map[string]persistentBoolean)
	var diagnostics []error
	for lineNumber, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "SELinux" {
			continue
		}
		_, stateAndDescription, hasState := strings.Cut(line, "(")
		state, description, hasDescription := strings.Cut(stateAndDescription, ")")
		if !hasState || !hasDescription {
			diagnostics = append(diagnostics, fmt.Errorf("semanage boolean line %d: malformed output", lineNumber+1))
			continue
		}
		parts := strings.FieldsFunc(state, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		if len(parts) != 2 || (parts[1] != "on" && parts[1] != "off") {
			diagnostics = append(diagnostics, fmt.Errorf("semanage boolean line %d: malformed state", lineNumber+1))
			continue
		}
		values[fields[0]] = persistentBoolean{Value: parts[1] == "on", Description: strings.TrimSpace(description)}
	}
	return values, diagnostics
}

func collectPolicyMetadata(diagnostics []error) (PolicyMetadata, []error) {
	var policy PolicyMetadata
	for _, packageName := range []string{"selinux-policy-targeted", "selinux-policy"} {
		value, err := exec.Command("rpm", "-q", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n", packageName).Output()
		if err == nil {
			fields := strings.Split(strings.TrimSpace(string(value)), "\t")
			if len(fields) == 5 {
				policy.Package = &PolicyPackage{Name: fields[0], Epoch: fields[1], Version: fields[2], Release: fields[3], Architecture: fields[4]}
			}
			break
		}
	}
	if policy.Package == nil {
		diagnostics = append(diagnostics, errors.New("policy package: rpm query unavailable"))
	}
	value, err := exec.Command("semodule", "-lfull").Output()
	if err != nil {
		diagnostics = append(diagnostics, errors.New("policy modules: semodule query unavailable"))
	} else {
		policy.Modules = parsePolicyModules(string(value))
		policy.Modules, diagnostics = annotateModuleProvenance(policy.Modules, diagnostics)
	}
	policy, diagnostics = collectFileContextMappings(policy, func(name string, args ...string) ([]byte, error) {
		command := exec.Command(name, args...)
		command.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=C")
		return command.Output()
	}, diagnostics)
	policy.PortInventory, diagnostics = collectPortInventory(diagnostics)
	return policy, diagnostics
}

func collectPortInventory(diagnostics []error) (*PortInventory, []error) {
	return collectPortInventoryWithRunner(func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}, diagnostics)
}

func collectPortInventoryWithRunner(run func(string, ...string) ([]byte, error), diagnostics []error) (*PortInventory, []error) {
	effectiveOutput, effectiveErr := run("semanage", "port", "-l", "-n")
	localOutput, localErr := run("semanage", "port", "-l", "-C", "-n")
	effective, effectiveDiagnostics := parsePortInventory(string(effectiveOutput))
	local, localDiagnostics := parseLocalPortInventory(string(localOutput))
	if effectiveErr != nil {
		effective.Status = "unavailable"
		effective.Mappings = nil
		diagnostics = append(diagnostics, errors.New("port mappings: semanage port listing unavailable"))
	} else {
		diagnostics = append(diagnostics, effectiveDiagnostics...)
	}
	if localErr != nil {
		local.Status = "unavailable"
		local.Mappings = nil
		diagnostics = append(diagnostics, errors.New("local port mappings: semanage port listing unavailable"))
	} else {
		diagnostics = append(diagnostics, localDiagnostics...)
	}
	inventory := &PortInventory{Status: effective.Status, Mappings: []PortMapping{}, LocalClassificationStatus: local.Status}
	if effective.Status == "observed" || effective.Status == "partial" {
		inventory.Mappings = reconcilePortMappings(effective.Mappings, local.Mappings, local.Status)
	}
	return inventory, diagnostics
}

type parsedPortMapping struct {
	Type     string
	Protocol string
	Ports    []PortRange
}

type parsedPortInventory struct {
	Status   string
	Mappings []parsedPortMapping
}

func parsePortInventory(output string) (parsedPortInventory, []error) {
	return parsePortInventoryWithFormat(output, false)
}

func parseLocalPortInventory(output string) (parsedPortInventory, []error) {
	return parsePortInventoryWithFormat(output, true)
}

func parsePortInventoryWithFormat(output string, emptyIsObserved bool) (parsedPortInventory, []error) {
	result := parsedPortInventory{Status: "unknown"}
	var diagnostics []error
	recognized := false
	headerSeen := false
	rejected := 0
	for lineNumber, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(line, "---") {
			continue
		}
		if fields[0] == "SELinux" {
			headerSeen = true
			recognized = len(fields) >= 5 && fields[1] == "Port" && fields[2] == "Type" && fields[3] == "Proto"
			if !recognized {
				diagnostics = append(diagnostics, fmt.Errorf("semanage port line %d: unrecognized header", lineNumber+1))
			}
			continue
		}
		if !recognized {
			if headerSeen {
				continue
			}
			recognized = true
		}
		if len(fields) < 3 {
			diagnostics = append(diagnostics, fmt.Errorf("semanage port line %d: malformed output", lineNumber+1))
			rejected++
			continue
		}
		ports, err := parsePortRanges(fields[2:], "")
		if err != nil {
			diagnostics = append(diagnostics, fmt.Errorf("semanage port line %d: %w", lineNumber+1, err))
			rejected++
			continue
		}
		result.Mappings = append(result.Mappings, parsedPortMapping{Type: fields[0], Protocol: fields[1], Ports: canonicalPortRanges(ports)})
	}
	if recognized {
		result.Status = "observed"
		if rejected > 0 {
			result.Status = "partial"
		}
	} else if emptyIsObserved && strings.TrimSpace(output) == "" {
		result.Status = "observed"
	}
	return result, diagnostics
}

func parsePortRanges(values []string, provenance string) ([]PortRange, error) {
	var result []PortRange
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			bounds := strings.Split(strings.TrimSpace(part), "-")
			if len(bounds) > 2 || bounds[0] == "" {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			start, err := strconv.ParseUint(bounds[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			end := start
			if len(bounds) == 2 {
				end, err = strconv.ParseUint(bounds[1], 10, 16)
				if err != nil || end < start {
					return nil, fmt.Errorf("invalid port range %q", part)
				}
			}
			result = append(result, PortRange{Start: uint16(start), End: uint16(end), Provenance: provenance})
		}
	}
	if len(result) == 0 {
		return nil, errors.New("empty port range")
	}
	return result, nil
}

func reconcilePortMappings(effective, local []parsedPortMapping, localStatus string) []PortMapping {
	localByKey := make(map[string][]PortRange)
	for _, mapping := range local {
		key := mapping.Type + "\x00" + mapping.Protocol
		localByKey[key] = append(localByKey[key], mapping.Ports...)
	}
	result := make(map[string]*PortMapping)
	for _, mapping := range effective {
		key := mapping.Type + "\x00" + mapping.Protocol
		entry := result[key]
		if entry == nil {
			entry = &PortMapping{Type: mapping.Type, Protocol: mapping.Protocol}
			result[key] = entry
		}
		for _, effectiveRange := range mapping.Ports {
			entry.Ports = append(entry.Ports, splitPortRange(effectiveRange, localByKey[key], localStatus)...)
		}
	}
	values := make([]PortMapping, 0, len(result))
	for _, mapping := range result {
		mapping.Ports = canonicalPortRanges(mapping.Ports)
		values = append(values, *mapping)
	}
	slices.SortFunc(values, func(a, b PortMapping) int {
		if order := cmp.Compare(a.Type, b.Type); order != 0 {
			return order
		}
		return cmp.Compare(a.Protocol, b.Protocol)
	})
	return values
}

func splitPortRange(value PortRange, locals []PortRange, localStatus string) []PortRange {
	boundaries := []uint32{uint32(value.Start), uint32(value.End) + 1}
	for _, local := range locals {
		if local.End < value.Start || local.Start > value.End {
			continue
		}
		if local.Start > value.Start && local.Start <= value.End {
			boundaries = append(boundaries, uint32(local.Start))
		}
		if local.End < value.End {
			boundaries = append(boundaries, uint32(local.End)+1)
		}
	}
	slices.Sort(boundaries)
	var result []PortRange
	for index := range len(boundaries) - 1 {
		start, end := boundaries[index], boundaries[index+1]-1
		provenance := "unknown"
		if localStatus == "observed" {
			provenance = "not_confirmed_custom"
		}
		for _, local := range locals {
			if start >= uint32(local.Start) && end <= uint32(local.End) {
				provenance = "custom"
				break
			}
		}
		result = append(result, PortRange{Start: uint16(start), End: uint16(end), Provenance: provenance})
	}
	return result
}

func canonicalPortRanges(ranges []PortRange) []PortRange {
	slices.SortFunc(ranges, func(a, b PortRange) int {
		if order := cmp.Compare(a.Start, b.Start); order != 0 {
			return order
		}
		if order := cmp.Compare(a.End, b.End); order != 0 {
			return order
		}
		return cmp.Compare(a.Provenance, b.Provenance)
	})
	result := make([]PortRange, 0, len(ranges))
	for _, current := range ranges {
		if len(result) > 0 && result[len(result)-1].Provenance == current.Provenance && uint32(current.Start) <= uint32(result[len(result)-1].End)+1 {
			if current.End > result[len(result)-1].End {
				result[len(result)-1].End = current.End
			}
			continue
		}
		result = append(result, current)
	}
	return result
}

func annotateModuleProvenance(modules []PolicyModule, diagnostics []error) ([]PolicyModule, []error) {
	for index, module := range modules {
		for _, path := range []string{
			"/usr/share/selinux/packages/targeted/" + module.Name + ".pp.bz2",
			"/usr/share/selinux/packages/targeted/" + module.Name + ".pp",
			"/usr/share/selinux/packages/" + module.Name + ".pp.bz2",
			"/usr/share/selinux/packages/" + module.Name + ".pp",
		} {
			value, err := exec.Command("rpm", "-qf", path).Output()
			if err == nil {
				packageName := strings.TrimSpace(string(value))
				if packageName != "" {
					modules[index].Provenance = "distribution"
					modules[index].SourcePackage = packageName
				}
				break
			}
		}
	}
	return modules, diagnostics
}

func parsePolicyModules(output string) []PolicyModule {
	var modules []PolicyModule
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		priority, err := strconv.Atoi(fields[0])
		// Local policy modules conventionally use a priority above the distro default.
		if err != nil || priority <= 100 {
			continue
		}
		module := PolicyModule{Name: fields[1], Priority: priority, Provenance: "unknown"}
		if len(fields) > 2 && fields[2] != "pp" {
			module.Version = fields[2]
		}
		modules = append(modules, module)
	}
	return modules
}

func parseFileContexts(output string, diagnostics []error) ([]FileContextMapping, []error) {
	var mappings []FileContextMapping
	inEquivalenceSection := false
	for lineNumber, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if strings.Contains(line, "Equivalence") {
			inEquivalenceSection = true
			continue
		}
		if inEquivalenceSection || len(fields) == 0 || strings.HasPrefix(line, "SELinux fcontext") || strings.HasPrefix(line, "----") {
			continue
		}
		if len(fields) < 2 || (fields[len(fields)-1] != "<<None>>" && !strings.Contains(fields[len(fields)-1], ":")) {
			diagnostics = append(diagnostics, fmt.Errorf("semanage fcontext line %d: malformed output", lineNumber+1))
			continue
		}
		mapping := FileContextMapping{Pattern: fields[0], Context: fields[len(fields)-1], Provenance: "distribution"}
		if len(fields) > 2 {
			mapping.FileType = strings.Join(fields[1:len(fields)-1], " ")
		}
		mappings = append(mappings, mapping)
	}
	slices.SortFunc(mappings, func(a, b FileContextMapping) int {
		if order := cmp.Compare(a.Pattern, b.Pattern); order != 0 {
			return order
		}
		return cmp.Compare(a.FileType, b.FileType)
	})
	return mappings, diagnostics
}

func fileContextKey(mapping FileContextMapping) string {
	return mapping.Pattern + "\x00" + mapping.FileType + "\x00" + mapping.Context
}

func hostID(machineID string) string {
	sum := sha256.Sum256([]byte("secentral-host-v1:" + strings.TrimSpace(machineID)))
	return hex.EncodeToString(sum[:])
}

func collectSELinux(root string, diagnostics []error) (SELinuxMetadata, []error) {
	return collectSELinuxWithReader(func(path string) (string, error) {
		return read(root, path)
	}, diagnostics)
}

func collectSELinuxWithReader(reader func(string) (string, error), diagnostics []error) (SELinuxMetadata, []error) {
	metadata := SELinuxMetadata{Enforcement: Disabled}
	if value, err := reader("/sys/fs/selinux/enforce"); err == nil {
		metadata.Enabled = true
		switch strings.TrimSpace(value) {
		case "1":
			metadata.Enforcement = Enforcing
		case "0":
			metadata.Enforcement = Permissive
		default:
			metadata.Enforcement = Unknown
			diagnostics = append(diagnostics, fmt.Errorf("selinux enforce: invalid value %q", strings.TrimSpace(value)))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		metadata.Enforcement = Unknown
		diagnostics = append(diagnostics, fmt.Errorf("selinux enforce: %w", err))
	}
	if value, err := reader("/sys/fs/selinux/policyvers"); err == nil {
		version, parseErr := strconv.Atoi(strings.TrimSpace(value))
		if parseErr != nil {
			diagnostics = append(diagnostics, fmt.Errorf("selinux policy version: %w", parseErr))
		} else {
			metadata.KernelPolicyVersion = new(version)
		}
	}
	if value, err := reader("/etc/selinux/config"); err == nil {
		config := parseConfig(value)
		if policyType := config["SELINUXTYPE"]; policyType != "" {
			metadata.ConfiguredPolicyType = new(policyType)
		}
	}
	return metadata, diagnostics
}

func parseOSRelease(contents string) (string, string, error) {
	values := parseConfig(contents)
	var diagnostics []error
	for lineNumber, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") {
			continue
		}
		diagnostics = append(diagnostics, fmt.Errorf("os-release line %d: missing '='", lineNumber+1))
	}
	return values["ID"], values["VERSION_ID"], errors.Join(diagnostics...)
}

func parseConfig(contents string) map[string]string {
	values := make(map[string]string)
	for line := range strings.SplitSeq(contents, "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, "=")
		if !found || strings.HasPrefix(line, "#") {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values
}

func read(root, path string) (string, error) {
	contents, err := os.ReadFile(filepath.Join(root, path))
	return string(contents), err
}

func kernelRelease() (string, error) {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "", err
	}
	buffer := make([]byte, 0, len(uts.Release))
	for _, value := range uts.Release {
		if value == 0 {
			break
		}
		buffer = append(buffer, byte(value))
	}
	return string(buffer), nil
}
