package metadata

import (
	"errors"
	"regexp"
	"strings"
)

var mappingRow = regexp.MustCompile(`^(/\S*)\s+(all files|regular file|directory|character device|block device|named pipe|symbolic link|socket)\s+(\S+)\s*$`)
var mappingContext = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z0-9_:.,+-]+)?$`)
var equivalenceRow = regexp.MustCompile(`^(/\S*)\s+=\s+(/\S*)$`)

// The listing is configuration evidence, not an implementation of regex lookup.
// Local listing order and equivalences are retained; matchpathcon owns resolution.
func collectFileContextMappings(policy PolicyMetadata, run func(string, ...string) ([]byte, error), diagnostics []error) (PolicyMetadata, []error) {
	effective, effectiveErr := run("semanage", "fcontext", "-l")
	local, localErr := run("semanage", "fcontext", "-l", "-C")
	mappings, equivalents, parseErrs := parseMappingInventory(string(effective), "distribution")
	locals, _, localParseErrs := parseMappingInventory(string(local), "custom")
	policy.FileContexts, policy.LocalFileContextMappings, policy.FileContextEquivalences = mappings, locals, equivalents
	diagnostics = append(diagnostics, parseErrs...)
	diagnostics = append(diagnostics, localParseErrs...)
	policy.FileContextMappingsStatus = "observed"
	if effectiveErr != nil || localErr != nil {
		diagnostics = append(diagnostics, errors.New("file-context mapping inventory: effective/local listing unavailable"))
		policy.FileContextMappingsStatus = "partial"
		if effectiveErr != nil && localErr != nil {
			policy.FileContextMappingsStatus = "unavailable"
		}
	} else if len(parseErrs)+len(localParseErrs) > 0 {
		policy.FileContextMappingsStatus = "partial"
	}
	keys := make(map[string]struct{}, len(locals))
	for _, mapping := range locals {
		keys[fileContextKey(mapping)] = struct{}{}
	}
	for i, mapping := range mappings {
		if _, found := keys[fileContextKey(mapping)]; found {
			policy.FileContexts[i].Provenance = "custom"
		}
	}
	return policy, diagnostics
}

func parseMappingInventory(output, provenance string) ([]FileContextMapping, []FileContextEquivalence, []error) {
	mappings := []FileContextMapping{}
	equivalents := []FileContextEquivalence{}
	var diagnostics []error
	equivalences := false
	equivalentProvenance := provenance
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "SELinux fcontext ") || strings.HasPrefix(line, "----") {
			continue
		}
		if line == "SELinux Distribution fcontext Equivalence" || line == "SELinux Local fcontext Equivalence" {
			equivalences = true
			equivalentProvenance = "distribution"
			if strings.Contains(line, "Local") {
				equivalentProvenance = "custom"
			}
			continue
		}
		if equivalences {
			match := equivalenceRow.FindStringSubmatch(line)
			if match == nil {
				diagnostics = append(diagnostics, errors.New("unparsed file-context equivalence"))
				continue
			}
			equivalents = append(equivalents, FileContextEquivalence{Source: match[1], Target: match[2], Provenance: equivalentProvenance})
			continue
		}
		match := mappingRow.FindStringSubmatch(line)
		if match == nil || (match[3] != "<<None>>" && !mappingContext.MatchString(match[3])) {
			diagnostics = append(diagnostics, errors.New("unparsed file-context mapping"))
			continue
		}
		key := match[1] + "\x00" + match[2]
		if seen[key] {
			diagnostics = append(diagnostics, errors.New("duplicate file-context mapping key"))
		}
		seen[key] = true
		mappings = append(mappings, FileContextMapping{Pattern: match[1], FileType: match[2], Context: match[3], Provenance: provenance})
	}
	return mappings, equivalents, diagnostics
}
