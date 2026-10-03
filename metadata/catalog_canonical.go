package metadata

import (
	"bytes"
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"unicode/utf8"
)

func canonicalCatalogJSON(catalog DistributionCatalog) ([]byte, error) {
	booleans := slices.Clone(catalog.Families.Booleans.Entries)
	slices.SortFunc(booleans, func(a, b CatalogBoolean) int { return cmp.Compare(a.Name, b.Name) })
	ports := slices.Clone(catalog.Families.Ports.Mappings)
	sortCatalogPorts(ports)
	packages := slices.Clone(catalog.Policy.Packages)
	sortCatalogPackages(packages)

	return canonicalJSON(map[string]any{
		"collector_semantics_version": catalog.CollectorSemanticsVersion,
		"families": map[string]any{
			"booleans": map[string]any{
				"complete": catalog.Families.Booleans.Complete,
				"entries":  canonicalBooleanEntries(booleans),
			},
			"ports": map[string]any{
				"complete": catalog.Families.Ports.Complete,
				"mappings": canonicalPortMappings(ports),
			},
		},
		"platform": map[string]any{
			"architecture":  catalog.Platform.Architecture,
			"distribution":  catalog.Platform.Distribution,
			"major_version": catalog.Platform.MajorVersion,
		},
		"policy": map[string]any{
			"kernel_policy_version": catalog.Policy.KernelPolicyVersion,
			"loaded_policy_digest":  catalog.Policy.LoadedPolicyDigest,
			"packages":              canonicalPolicyPackages(packages),
			"type":                  catalog.Policy.Type,
		},
	})
}

func canonicalBooleanEntries(entries []CatalogBoolean) []any {
	result := make([]any, 0, len(entries))
	for _, entry := range entries {
		result = append(result, map[string]any{"default": entry.Default, "description": entry.Description, "name": entry.Name})
	}
	return result
}

func canonicalPortMappings(mappings []CatalogPortMapping) []any {
	result := make([]any, 0, len(mappings))
	for _, mapping := range mappings {
		result = append(result, map[string]any{"end": mapping.End, "protocol": mapping.Protocol, "start": mapping.Start, "type": mapping.Type})
	}
	return result
}

func canonicalPolicyPackages(packages []PolicyPackage) []any {
	result := make([]any, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, map[string]any{"architecture": pkg.Architecture, "epoch": pkg.Epoch, "name": pkg.Name, "release": pkg.Release, "version": pkg.Version})
	}
	return result
}

func sortCatalogPackages(packages []PolicyPackage) {
	slices.SortFunc(packages, func(a, b PolicyPackage) int {
		if order := cmp.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Epoch, b.Epoch); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Version, b.Version); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Release, b.Release); order != 0 {
			return order
		}
		return cmp.Compare(a.Architecture, b.Architecture)
	})
}

func equalCatalogPackages(left, right []PolicyPackage) bool {
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

func canonicalJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := writeCanonicalJSON(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonicalJSON(output *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(value))
	case string:
		if !utf8.ValidString(value) {
			return fmt.Errorf("canonical JSON string is not UTF-8")
		}
		writeCanonicalJSONString(output, value)
	case int:
		output.WriteString(strconv.Itoa(value))
	case uint16:
		output.WriteString(strconv.FormatUint(uint64(value), 10))
	case []any:
		output.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := slices.Sorted(maps.Keys(value))
		for _, key := range keys {
			if !utf8.ValidString(key) {
				return fmt.Errorf("canonical JSON object key is not UTF-8")
			}
		}
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			writeCanonicalJSONString(output, key)
			output.WriteByte(':')
			if err := writeCanonicalJSON(output, value[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func writeCanonicalJSONString(output *bytes.Buffer, value string) {
	output.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if character < 0x20 {
				fmt.Fprintf(output, `\u%04x`, character)
			} else {
				output.WriteRune(character)
			}
		}
	}
	output.WriteByte('"')
}
