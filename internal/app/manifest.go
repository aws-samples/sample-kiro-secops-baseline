package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const managedManifestVersion = 1

type managedManifest struct {
	Version     int             `json:"version"`
	Scope       string          `json:"scope"`
	ToolVersion string          `json:"toolVersion"`
	UpdatedAt   string          `json:"updatedAt"`
	Entries     []manifestEntry `json:"entries"`
}

type manifestEntry struct {
	Path            string        `json:"path"`
	InstalledSHA256 string        `json:"installedSha256"`
	Mode            uint32        `json:"mode"`
	Previous        previousState `json:"previous"`
}

type previousState struct {
	Existed      bool   `json:"existed"`
	Backup       string `json:"backup,omitempty"`
	BackupSHA256 string `json:"backupSha256,omitempty"`
	Mode         uint32 `json:"mode,omitempty"`
}

type managedTransaction struct {
	root           *safeRoot
	opts           *opts
	scope          string
	manifestPath   string
	backupBase     string
	transactionID  string
	entries        map[string]manifestEntry
	touched        []transactionTouch
	touchedPaths   map[string]bool
	createdBackups []string
	closed         bool
}

type transactionTouch struct {
	path     string
	previous fileSnapshot
}

type restorePlan struct {
	entry    manifestEntry
	current  fileSnapshot
	previous fileSnapshot
}

func beginManagedTransaction(root *safeRoot, scope, manifestPath, backupBase string, o *opts) (*managedTransaction, error) {
	if _, err := root.cleanRel(manifestPath); err != nil {
		return nil, err
	}
	if _, err := root.cleanRel(backupBase); err != nil {
		return nil, err
	}
	id, err := randomToken(8)
	if err != nil {
		return nil, err
	}
	m, found, err := loadManagedManifest(root, scope, manifestPath, backupBase)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]manifestEntry)
	if found {
		for _, entry := range m.Entries {
			entries[entry.Path] = entry
		}
	}
	return &managedTransaction{
		root:          root,
		opts:          o,
		scope:         scope,
		manifestPath:  filepath.Clean(filepath.FromSlash(manifestPath)),
		backupBase:    filepath.Clean(filepath.FromSlash(backupBase)),
		transactionID: id,
		entries:       entries,
		touchedPaths:  make(map[string]bool),
	}, nil
}

// persistBackup writes (durably) the original content to backupRel before overwriting.
func (t *managedTransaction) persistBackup(backupRel string, data []byte) error {
	existing, err := t.root.snapshot(backupRel)
	if err != nil {
		return err
	}
	if existing.exists {
		return fmt.Errorf("managed backup unexpectedly already exists: %s", t.root.display(backupRel))
	}
	if err := t.root.atomicWrite(backupRel, data, 0o600); err != nil {
		return fmt.Errorf("persist backup of the original: %w", err)
	}
	t.createdBackups = append(t.createdBackups, backupRel)
	return nil
}

func (t *managedTransaction) Read(path string) ([]byte, os.FileMode, bool, error) {
	snap, err := t.root.snapshot(path)
	if err != nil {
		return nil, 0, false, err
	}
	if !snap.exists {
		return nil, 0, false, nil
	}
	return append([]byte(nil), snap.data...), snap.mode, true, nil
}

func (t *managedTransaction) Write(path string, data []byte, perm os.FileMode) error {
	if t.closed {
		return errors.New("transaction already closed")
	}
	clean, err := t.root.cleanRel(path)
	if err != nil {
		return err
	}
	if t.touchedPaths[clean] {
		return fmt.Errorf("file written more than once in the same transaction: %s", clean)
	}
	current, err := t.root.snapshot(clean)
	if err != nil {
		return err
	}

	entry, wasManaged := t.entries[clean]
	if wasManaged {
		matches := current.exists && hashBytes(current.data) == entry.InstalledSHA256
		if !matches && !t.opts.force {
			return fmt.Errorf("managed artifact was modified: %s (use --force to replace)", t.root.display(clean))
		}
	} else {
		entry.Path = clean
		entry.Previous = previousState{Existed: current.exists}
		if current.exists {
			backupRel := filepath.Join(t.backupBase, t.transactionID, hashBytes([]byte(clean))+".bak")
			entry.Previous.Backup = backupRel
			entry.Previous.BackupSHA256 = hashBytes(current.data)
			entry.Previous.Mode = uint32(current.mode.Perm())
			// WRITE-AHEAD: persist the original's backup BEFORE overwriting.
			// This way, a crash in the middle of the transaction never loses the original
			// content (it remains recoverable under <backupBase>/<txid>/), unlike keeping it
			// only in memory. Only happens outside dry-run.
			if !t.opts.dryRun {
				if err := t.persistBackup(backupRel, current.data); err != nil {
					_ = t.rollback()
					return err
				}
			}
		}
	}

	if t.opts.dryRun {
		fmt.Printf("  [dry-run] write %s (%d bytes)\n", t.root.display(clean), len(data))
	} else {
		t.touched = append(t.touched, transactionTouch{path: clean, previous: current})
		if err := t.root.atomicWrite(clean, data, perm); err != nil {
			_ = t.rollback()
			return err
		}
	}
	t.touchedPaths[clean] = true
	entry.InstalledSHA256 = hashBytes(data)
	entry.Mode = uint32(perm.Perm())
	if current.exists {
		entry.Mode = uint32(current.mode.Perm())
	}
	t.entries[clean] = entry
	return nil
}

func (t *managedTransaction) Commit() error {
	if t.closed {
		return errors.New("transaction already closed")
	}
	if t.opts.dryRun {
		fmt.Printf("  [dry-run] update manifest %s\n", t.root.display(t.manifestPath))
		t.closed = true
		return nil
	}

	// The backups were already persisted (write-ahead) during each Write. Here it only
	// remains to write the manifest, which "seals" the transaction and enables restoration.
	entries := make([]manifestEntry, 0, len(t.entries))
	for _, entry := range t.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	m := managedManifest{
		Version:     managedManifestVersion,
		Scope:       t.scope,
		ToolVersion: version,
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Entries:     entries,
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		_ = t.rollback()
		return fmt.Errorf("serialize manifest: %w", err)
	}
	data = append(data, '\n')
	if err := t.root.atomicWrite(t.manifestPath, data, 0o600); err != nil {
		_ = t.rollback()
		return fmt.Errorf("write manifest: %w", err)
	}
	t.closed = true
	t.touched = nil
	return nil
}

func (t *managedTransaction) Rollback() error { return t.rollback() }

func (t *managedTransaction) rollback() error {
	if t.closed {
		return nil
	}
	var errs []error
	for i := len(t.touched) - 1; i >= 0; i-- {
		touch := t.touched[i]
		if err := t.root.restore(touch.path, touch.previous); err != nil {
			errs = append(errs, fmt.Errorf("rollback %s: %w", touch.path, err))
		}
	}
	// Remove the backups persisted by this transaction (write-ahead) — since the
	// manifest was not sealed, they should not remain.
	for _, backup := range t.createdBackups {
		if err := t.root.removeFile(backup); err != nil {
			errs = append(errs, fmt.Errorf("clean up backup %s: %w", backup, err))
		}
	}
	if len(t.createdBackups) > 0 {
		_ = t.root.removeAll(filepath.Join(t.backupBase, t.transactionID))
	}
	t.closed = true
	return errors.Join(errs...)
}

// integrityStatus describes the state of a managed artifact relative to the manifest.
type integrityStatus struct {
	Path   string
	Status string // "OK", "MISSING", "MODIFIED", or "ERROR"
}

func (s integrityStatus) ok() bool { return s.Status == "OK" }

// verifyManaged compares each registered artifact against the hash recorded in the manifest.
// It returns the status list and an error only when the manifest is missing/invalid.
func verifyManaged(root *safeRoot, scope, manifestPath, backupBase string) ([]integrityStatus, error) {
	m, found, err := loadManagedManifest(root, scope, manifestPath, backupBase)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("managed manifest missing: %s", root.display(manifestPath))
	}
	report := make([]integrityStatus, 0, len(m.Entries))
	for _, entry := range m.Entries {
		status := integrityStatus{Path: entry.Path, Status: "OK"}
		snap, snapErr := root.snapshot(entry.Path)
		switch {
		case snapErr != nil:
			status.Status = "ERROR"
		case !snap.exists:
			status.Status = "MISSING"
		case hashBytes(snap.data) != entry.InstalledSHA256:
			status.Status = "MODIFIED"
		}
		report = append(report, status)
	}
	return report, nil
}

func restoreManaged(root *safeRoot, scope, manifestPath, backupBase string, o *opts) error {
	m, found, err := loadManagedManifest(root, scope, manifestPath, backupBase)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("managed manifest missing; refusing to remove files without proof of ownership: %s", root.display(manifestPath))
	}

	plans := make([]restorePlan, 0, len(m.Entries))
	for _, entry := range m.Entries {
		current, err := root.snapshot(entry.Path)
		if err != nil {
			return err
		}
		if current.exists && hashBytes(current.data) != entry.InstalledSHA256 && !o.force {
			return fmt.Errorf("managed artifact was modified: %s (use --force to restore anyway)", root.display(entry.Path))
		}
		previous := fileSnapshot{}
		if entry.Previous.Existed {
			backup, err := root.snapshot(entry.Previous.Backup)
			if err != nil {
				return err
			}
			if !backup.exists {
				return fmt.Errorf("original backup missing: %s", root.display(entry.Previous.Backup))
			}
			if hashBytes(backup.data) != entry.Previous.BackupSHA256 {
				return fmt.Errorf("invalid integrity of the original backup: %s", root.display(entry.Previous.Backup))
			}
			previous = fileSnapshot{exists: true, data: backup.data, mode: os.FileMode(entry.Previous.Mode)}
		}
		plans = append(plans, restorePlan{entry: entry, current: current, previous: previous})
	}

	if o.dryRun {
		for _, plan := range plans {
			action := "remove"
			if plan.previous.exists {
				action = "restore"
			}
			fmt.Printf("  [dry-run] %s %s\n", action, root.display(plan.entry.Path))
		}
		fmt.Printf("  [dry-run] remove manifest %s\n", root.display(manifestPath))
		return nil
	}

	applied := make([]restorePlan, 0, len(plans))
	rollback := func() error {
		var errs []error
		for i := len(applied) - 1; i >= 0; i-- {
			plan := applied[i]
			if err := root.restore(plan.entry.Path, plan.current); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	for _, plan := range plans {
		if err := root.restore(plan.entry.Path, plan.previous); err != nil {
			_ = rollback()
			return fmt.Errorf("restore %s: %w", root.display(plan.entry.Path), err)
		}
		applied = append(applied, plan)
	}
	if err := root.removeFile(manifestPath); err != nil {
		_ = rollback()
		return fmt.Errorf("remove manifest: %w", err)
	}
	if err := root.removeAll(backupBase); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not clean up backups that were already restored:", err)
	}
	return nil
}

func loadManagedManifest(root *safeRoot, scope, manifestPath, backupBase string) (managedManifest, bool, error) {
	snap, err := root.snapshot(manifestPath)
	if err != nil {
		return managedManifest{}, false, err
	}
	if !snap.exists {
		return managedManifest{}, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(snap.data))
	dec.DisallowUnknownFields()
	var m managedManifest
	if err := dec.Decode(&m); err != nil {
		return managedManifest{}, false, fmt.Errorf("invalid manifest %s: %w", root.display(manifestPath), err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return managedManifest{}, false, fmt.Errorf("invalid manifest %s: %w", root.display(manifestPath), err)
	}
	if m.Version != managedManifestVersion {
		return managedManifest{}, false, fmt.Errorf("unsupported manifest version: %d", m.Version)
	}
	if m.Scope != scope {
		return managedManifest{}, false, fmt.Errorf("unexpected manifest scope: %q", m.Scope)
	}
	seen := make(map[string]bool)
	backupPrefix := filepath.Clean(filepath.FromSlash(backupBase)) + string(filepath.Separator)
	for i := range m.Entries {
		entry := &m.Entries[i]
		clean, err := root.cleanRel(entry.Path)
		if err != nil || clean != filepath.Clean(filepath.FromSlash(entry.Path)) {
			return managedManifest{}, false, fmt.Errorf("invalid path in the manifest: %q", entry.Path)
		}
		entry.Path = clean
		if seen[clean] {
			return managedManifest{}, false, fmt.Errorf("duplicate entry in the manifest: %s", clean)
		}
		seen[clean] = true
		if len(entry.InstalledSHA256) != sha256.Size*2 {
			return managedManifest{}, false, fmt.Errorf("invalid installed hash for %s", clean)
		}
		if entry.Previous.Existed {
			backup, err := root.cleanRel(entry.Previous.Backup)
			if err != nil || !strings.HasPrefix(backup, backupPrefix) {
				return managedManifest{}, false, fmt.Errorf("backup outside the managed area for %s", clean)
			}
			entry.Previous.Backup = backup
			if len(entry.Previous.BackupSHA256) != sha256.Size*2 {
				return managedManifest{}, false, fmt.Errorf("invalid backup hash for %s", clean)
			}
		} else if entry.Previous.Backup != "" || entry.Previous.BackupSHA256 != "" {
			return managedManifest{}, false, fmt.Errorf("unexpected backup for a file originally missing: %s", clean)
		}
	}
	return m, true, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("extra content after the JSON document")
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
