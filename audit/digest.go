package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// EvidenceDigest hashes the evidence, not its JSON representation. This keeps
// duplicate detection stable when optional wire fields are added.
func EvidenceDigest(event Event) string {
	digest := sha256.New()
	writeString(digest, string(event.Completion))
	writeUint64(digest, uint64(len(event.Records)))
	for _, record := range event.Records {
		writeUint64(digest, uint64(record.Position))
		writeUint64(digest, uint64(record.Type))
		writeString(digest, record.Timestamp.UTC().String())
		writeUint64(digest, uint64(record.Sequence))
		writeUint64(digest, uint64(len(record.Raw)))
		_, _ = digest.Write(record.Raw)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeString(digest hash.Hash, value string) {
	writeUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}
