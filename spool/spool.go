package spool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/secentral/agent/audit"
	"github.com/secentral/agent/protocol"
)

const SpoolVersion = 2

const (
	defaultMaxExpectedContextObservations = 1024
	defaultMaxExpectedContextBytes        = 16 << 20
)

type Config struct {
	MaxBytes                       int64
	MaxEvents                      int
	MaxExpectedContextBytes        int64
	MaxExpectedContextObservations int
}

type Item struct {
	SpoolVersion                int                    `json:"spool_version"`
	SchemaVersion               int                    `json:"schema_version"`
	Agent                       protocol.AgentMetadata `json:"agent"`
	HostID                      string                 `json:"host_id"`
	BootID                      string                 `json:"boot_id"`
	HostObservedAt              *time.Time             `json:"host_observed_at,omitempty"`
	CheckpointInvalidatedFields []string               `json:"checkpoint_invalidated_fields,omitempty"`
	Event                       audit.Event            `json:"event"`
	EvidenceDigest              string                 `json:"evidence_digest"`
}

type Entry struct {
	ID   string
	Item Item
}

type ExpectedContextEntry struct {
	ID   string
	Item protocol.ExpectedContextObservationRequest
}

type ScanResult struct {
	Entries     []Entry
	Diagnostics []error
}

type ExpectedContextScanResult struct {
	Entries     []ExpectedContextEntry
	Diagnostics []error
}

type Spool struct {
	// ponytail: serialize filesystem operations; per-entry locking only if measured contention warrants it.
	mu                     sync.Mutex
	expectedContextMu      sync.Mutex
	config                 Config
	pending                string
	blocked                string
	expectedContextPending string
	expectedContextBlocked string
	temporary              string
}

func New(root string, config Config) (*Spool, error) {
	if config.MaxBytes <= 0 {
		config.MaxBytes = 1 << 30
	}
	if config.MaxEvents <= 0 {
		config.MaxEvents = 10000
	}
	if config.MaxExpectedContextBytes <= 0 {
		config.MaxExpectedContextBytes = defaultMaxExpectedContextBytes
	}
	if config.MaxExpectedContextObservations <= 0 {
		config.MaxExpectedContextObservations = defaultMaxExpectedContextObservations
	}
	s := &Spool{
		config:                 config,
		pending:                filepath.Join(root, "pending"),
		blocked:                filepath.Join(root, "blocked"),
		expectedContextPending: filepath.Join(root, "expected-context", "pending"),
		expectedContextBlocked: filepath.Join(root, "expected-context", "blocked"),
		temporary:              filepath.Join(root, "tmp"),
	}
	for _, directory := range []string{s.pending, s.blocked, s.expectedContextPending, s.expectedContextBlocked, s.temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, err
		}
	}
	if entries, err := os.ReadDir(s.temporary); err == nil {
		for _, entry := range entries {
			if err := os.Remove(filepath.Join(s.temporary, entry.Name())); err != nil {
				return nil, fmt.Errorf("remove temporary spool entry %q: %w", entry.Name(), err)
			}
		}
	}
	return s, nil
}

func (s *Spool) Put(item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item.SpoolVersion = SpoolVersion
	if item.SchemaVersion == 0 {
		item.SchemaVersion = protocol.SchemaVersion
	}
	if item.EvidenceDigest == "" {
		item.EvidenceDigest = audit.EvidenceDigest(item.Event)
	}
	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("serialize spool entry: %w", err)
	}
	id := entryID(item)
	return s.persist(s.pending, id, data, s.config.MaxEvents, s.config.MaxBytes, s.pending, s.blocked)
}

func (s *Spool) PutExpectedContextObservation(item protocol.ExpectedContextObservationRequest) error {
	if err := item.Validate(); err != nil {
		return fmt.Errorf("invalid expected-context observation: %w", err)
	}
	data, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("serialize expected-context observation: %w", err)
	}
	s.expectedContextMu.Lock()
	defer s.expectedContextMu.Unlock()
	return s.persist(
		s.expectedContextPending,
		expectedContextEntryID(item),
		data,
		s.config.MaxExpectedContextObservations,
		s.config.MaxExpectedContextBytes,
		s.expectedContextPending,
		s.expectedContextBlocked,
	)
}

func (s *Spool) persist(pending, id string, data []byte, maxEntries int, maxBytes int64, capacityDirectories ...string) error {
	path := filepath.Join(pending, id+".json")
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(data) {
			return syncDirectory(pending)
		}
		return fmt.Errorf("spool entry %s already contains different evidence", id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if count, size, err := directoryUsage(capacityDirectories...); err != nil {
		return err
	} else if count >= maxEntries || size+int64(len(data)) > maxBytes {
		return errors.New("spool capacity exceeded")
	}
	temporary, err := os.CreateTemp(s.temporary, "entry-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return syncDirectory(pending)
}

func (s *Spool) Pending() (ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.load(s.pending)
	if err != nil {
		return ScanResult{}, err
	}
	slices.SortFunc(result.Entries, func(a, b Entry) int {
		left, right := a.Item.Event.AgentReceivedAt, b.Item.Event.AgentReceivedAt
		if left.Before(right) {
			return -1
		}
		if left.After(right) {
			return 1
		}
		return 0
	})
	return result, nil
}

func (s *Spool) ExpectedContextPending() (ExpectedContextScanResult, error) {
	s.expectedContextMu.Lock()
	defer s.expectedContextMu.Unlock()

	files, err := os.ReadDir(s.expectedContextPending)
	if err != nil {
		return ExpectedContextScanResult{}, err
	}
	var result ExpectedContextScanResult
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".json")
		path := filepath.Join(s.expectedContextPending, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, err)
			continue
		}
		var item protocol.ExpectedContextObservationRequest
		if err = json.Unmarshal(data, &item); err == nil {
			err = item.Validate()
		}
		if err != nil || expectedContextEntryID(item) != id {
			if quarantineErr := s.quarantineExpectedContext(file.Name()); quarantineErr != nil {
				result.Diagnostics = append(result.Diagnostics, quarantineErr)
			}
			if err == nil {
				err = errors.New("filename does not match observation identity")
			}
			result.Diagnostics = append(result.Diagnostics, fmt.Errorf("expected-context spool entry %s: %w", id, err))
			continue
		}
		result.Entries = append(result.Entries, ExpectedContextEntry{ID: id, Item: item})
	}
	slices.SortFunc(result.Entries, func(a, b ExpectedContextEntry) int {
		return a.Item.Observation.ObservedAt.Compare(b.Item.Observation.ObservedAt)
	})
	return result, nil
}

func (s *Spool) AckExpectedContextObservation(id string) error {
	s.expectedContextMu.Lock()
	defer s.expectedContextMu.Unlock()
	return s.removeExpectedContext(id)
}

func (s *Spool) BlockExpectedContextObservation(id string) error {
	s.expectedContextMu.Lock()
	defer s.expectedContextMu.Unlock()
	source := expectedContextPath(s.expectedContextPending, id)
	destination := expectedContextPath(s.expectedContextBlocked, id)
	if source == "" || destination == "" {
		return errors.New("invalid expected-context spool ID")
	}
	if err := os.Rename(source, destination); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, destinationErr := os.Stat(destination); destinationErr == nil {
				return errors.Join(syncDirectory(s.expectedContextPending), syncDirectory(s.expectedContextBlocked))
			}
		}
		return err
	}
	if err := syncDirectory(s.expectedContextPending); err != nil {
		return err
	}
	return syncDirectory(s.expectedContextBlocked)
}

func (s *Spool) removeExpectedContext(id string) error {
	path := expectedContextPath(s.expectedContextPending, id)
	if path == "" {
		return errors.New("invalid expected-context spool ID")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.expectedContextPending)
}

func (s *Spool) quarantineExpectedContext(name string) error {
	if err := os.Rename(filepath.Join(s.expectedContextPending, name), filepath.Join(s.expectedContextBlocked, name)); err != nil {
		return err
	}
	return errors.Join(syncDirectory(s.expectedContextPending), syncDirectory(s.expectedContextBlocked))
}

func expectedContextPath(directory, id string) string {
	if filepath.Base(id) != id {
		return ""
	}
	if filepath.Ext(id) != ".json" {
		id += ".json"
	}
	return filepath.Join(directory, id)
}

func expectedContextEntryID(item protocol.ExpectedContextObservationRequest) string {
	identity := strings.Join([]string{
		item.HostID,
		item.BootID,
		item.AuditEvent.Timestamp.UTC().String(),
		fmt.Sprint(item.AuditEvent.Sequence),
		item.Observation.Path,
		item.Observation.ObjectClass,
		item.Observation.FileType,
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func (s *Spool) Ack(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path(s.pending, id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return syncDirectory(s.pending)
		}
		return err
	}
	return syncDirectory(s.pending)
}

func (s *Spool) Block(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	source, destination := s.path(s.pending, id), s.path(s.blocked, id)
	if err := os.Rename(source, destination); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, destinationErr := os.Stat(destination); destinationErr == nil {
				return errors.Join(syncDirectory(s.pending), syncDirectory(s.blocked))
			}
		}
		return err
	}
	if err := syncDirectory(s.pending); err != nil {
		return err
	}
	return syncDirectory(s.blocked)
}

func (s *Spool) load(directory string) (ScanResult, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return ScanResult{}, err
	}
	var result ScanResult
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".json")
		data, err := os.ReadFile(filepath.Join(directory, file.Name()))
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, err)
			continue
		}
		var item Item
		if err := json.Unmarshal(data, &item); err != nil || item.SpoolVersion != SpoolVersion {
			if quarantineErr := s.quarantine(directory, file.Name()); quarantineErr != nil {
				result.Diagnostics = append(result.Diagnostics, quarantineErr)
			}
			if err == nil {
				err = fmt.Errorf("unsupported spool version %d", item.SpoolVersion)
			}
			result.Diagnostics = append(result.Diagnostics, fmt.Errorf("spool entry %s: %w", id, err))
			continue
		}
		if err := s.validateEntry(id, item); err != nil {
			if quarantineErr := s.quarantine(directory, file.Name()); quarantineErr != nil {
				result.Diagnostics = append(result.Diagnostics, quarantineErr)
			}
			result.Diagnostics = append(result.Diagnostics, fmt.Errorf("spool entry %s: %w", id, err))
			continue
		}
		result.Entries = append(result.Entries, Entry{ID: id, Item: item})
	}
	return result, nil
}

func (s *Spool) validateEntry(id string, item Item) error {
	if entryID(item) != id {
		return errors.New("filename does not match event identity")
	}
	if item.EvidenceDigest == "" || item.EvidenceDigest != audit.EvidenceDigest(item.Event) {
		return errors.New("evidence digest mismatch")
	}
	request := protocol.IngestRequest{
		SchemaVersion:               item.SchemaVersion,
		Agent:                       item.Agent,
		HostID:                      item.HostID,
		BootID:                      item.BootID,
		HostObservedAt:              item.HostObservedAt,
		CheckpointInvalidatedFields: item.CheckpointInvalidatedFields,
		Events:                      []audit.Event{item.Event},
	}
	if err := request.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}
	return nil
}

func (s *Spool) quarantine(directory, name string) error {
	if err := os.Rename(filepath.Join(directory, name), filepath.Join(s.blocked, name)); err != nil {
		return err
	}
	return errors.Join(syncDirectory(directory), syncDirectory(s.blocked))
}

func (s *Spool) path(directory, id string) string {
	if filepath.Base(id) != id || filepath.Ext(id) != ".json" {
		id += ".json"
	}
	return filepath.Join(directory, id)
}

func entryID(item Item) string {
	identity := item.HostID + "\x00" + item.BootID + "\x00" + item.Event.ID.Timestamp.UTC().String() + "\x00" + fmt.Sprint(item.Event.ID.Sequence)
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

func directoryUsage(directories ...string) (int, int64, error) {
	var count int
	var size int64
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return 0, 0, err
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return 0, 0, err
			}
			count++
			size += info.Size()
		}
	}
	return count, size, nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
