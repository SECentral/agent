package metadata

import (
	"errors"
	"testing"
)

func TestCompleteMappingInventoryPreservesLocalOrderAndEquivalences(t *testing.T) {
	effective := "SELinux fcontext type Context\n/ directory system_u:object_r:root_t:s0\n/srv/test(/.*)? all files system_u:object_r:httpd_sys_content_t:s0\n/srv/test/file regular file system_u:object_r:user_home_t:s0\nSELinux Distribution fcontext Equivalence\n/bin = /usr/bin\n"
	local := "/srv/test(/.*)? all files system_u:object_r:httpd_sys_content_t:s0\n/srv/test/file regular file system_u:object_r:user_home_t:s0\n"
	result, diagnostics := collectFileContextMappings(PolicyMetadata{}, func(_ string, args ...string) ([]byte, error) {
		if len(args) == 3 {
			return []byte(local), nil
		}
		return []byte(effective), nil
	}, nil)
	if len(diagnostics) != 0 || result.FileContextMappingsStatus != "observed" || len(result.FileContexts) != 3 || len(result.LocalFileContextMappings) != 2 || len(result.FileContextEquivalences) != 1 {
		t.Fatalf("%#v %v", result, diagnostics)
	}
	if result.LocalFileContextMappings[0].Pattern != "/srv/test(/.*)?" || result.FileContexts[1].Provenance != "custom" {
		t.Fatal("lost local ordering/provenance")
	}
	empty, _ := collectFileContextMappings(PolicyMetadata{}, func(string, ...string) ([]byte, error) { return nil, nil }, nil)
	if empty.FileContextMappingsStatus != "observed" || empty.FileContexts == nil || empty.LocalFileContextMappings == nil || empty.FileContextEquivalences == nil {
		t.Fatal("observed empty inventory lost")
	}
}
func TestMappingInventoryFailsClosedOnPartialAndUnavailableCollection(t *testing.T) {
	for _, fail := range []bool{false, true} {
		result, _ := collectFileContextMappings(PolicyMetadata{}, func(_ string, args ...string) ([]byte, error) {
			if fail {
				return nil, errors.New("missing")
			}
			return []byte("unparsed row\n"), nil
		}, nil)
		expected := "partial"
		if fail {
			expected = "unavailable"
		}
		if result.FileContextMappingsStatus != expected {
			t.Fatal(result.FileContextMappingsStatus)
		}
	}
	result, _ := collectFileContextMappings(PolicyMetadata{}, func(_ string, args ...string) ([]byte, error) {
		if len(args) == 3 {
			return nil, errors.New("local failed")
		}
		return []byte("/srv all files system_u:object_r:var_t:s0\n"), nil
	}, nil)
	if result.FileContextMappingsStatus != "partial" {
		t.Fatal("failed local listing reconciled mappings")
	}
}
