package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// safeRoot confines all managed operations to a root opened by os.OpenRoot.
// Beyond the confinement provided by Go, we reject symlinks in existing components
// so that the logical path recorded in the manifest is also the physical path used.
type safeRoot struct {
	base   string
	root   *os.Root
	dryRun bool
}

type fileSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func openSafeRoot(base string, create bool, o *opts) (*safeRoot, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	fi, err := os.Lstat(abs)
	if errors.Is(err, fs.ErrNotExist) {
		if !create {
			return nil, fmt.Errorf("root does not exist: %s", abs)
		}
		if o.dryRun {
			return &safeRoot{base: abs, dryRun: true}, nil
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return nil, fmt.Errorf("create root %s: %w", abs, err)
		}
		fi, err = os.Lstat(abs)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect root %s: %w", abs, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("root cannot be a symlink: %s", abs)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", abs)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("open safe root %s: %w", abs, err)
	}
	return &safeRoot{base: abs, root: root, dryRun: o.dryRun}, nil
}

func (r *safeRoot) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	return r.root.Close()
}

func (r *safeRoot) cleanRel(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.VolumeName(name) != "" ||
		strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("managed path must be relative: %q", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("managed path escapes the root: %q", name)
	}
	return clean, nil
}

func (r *safeRoot) display(rel string) string { return filepath.Join(r.base, rel) }

func (r *safeRoot) validateNoSymlinks(rel string, includeFinal bool) error {
	if r.root == nil {
		return nil
	}
	clean, err := r.cleanRel(rel)
	if err != nil {
		return err
	}
	parts := strings.Split(clean, string(filepath.Separator))
	limit := len(parts)
	if !includeFinal {
		limit--
	}
	current := ""
	for i := 0; i < limit; i++ {
		current = filepath.Join(current, parts[i])
		fi, statErr := r.root.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("inspect %s: %w", r.display(current), statErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink refused in managed path: %s", r.display(current))
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return fmt.Errorf("component is not a directory: %s", r.display(current))
		}
	}
	return nil
}

func (r *safeRoot) ensureDir(rel string, perm os.FileMode) error {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return err
	}
	if err := r.validateNoSymlinks(clean, true); err != nil {
		return err
	}
	if r.dryRun {
		fmt.Printf("  [dry-run] mkdir -p %s\n", r.display(clean))
		return nil
	}
	if err := r.root.MkdirAll(clean, perm); err != nil {
		return fmt.Errorf("create directory %s: %w", r.display(clean), err)
	}
	return nil
}

func (r *safeRoot) snapshot(rel string) (fileSnapshot, error) {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return fileSnapshot{}, err
	}
	if r.root == nil {
		return fileSnapshot{}, nil
	}
	if err := r.validateNoSymlinks(clean, true); err != nil {
		return fileSnapshot{}, err
	}
	fi, err := r.root.Lstat(clean)
	if errors.Is(err, fs.ErrNotExist) {
		return fileSnapshot{}, nil
	}
	if err != nil {
		return fileSnapshot{}, fmt.Errorf("inspect %s: %w", r.display(clean), err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fileSnapshot{}, fmt.Errorf("symlink refused in managed file: %s", r.display(clean))
	}
	if !fi.Mode().IsRegular() {
		return fileSnapshot{}, fmt.Errorf("managed file is not regular: %s", r.display(clean))
	}
	data, err := r.root.ReadFile(clean)
	if err != nil {
		return fileSnapshot{}, fmt.Errorf("read %s: %w", r.display(clean), err)
	}
	return fileSnapshot{exists: true, data: data, mode: fi.Mode().Perm()}, nil
}

func (r *safeRoot) atomicWrite(rel string, data []byte, perm os.FileMode) error {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return err
	}
	current, err := r.snapshot(clean)
	if err != nil {
		return err
	}
	mode := perm.Perm()
	if current.exists {
		mode = current.mode.Perm()
	}
	if r.dryRun {
		fmt.Printf("  [dry-run] write %s (%d bytes)\n", r.display(clean), len(data))
		return nil
	}
	parent := filepath.Dir(clean)
	if parent != "." {
		if err := r.ensureDir(parent, 0o755); err != nil {
			return err
		}
	}
	token, err := randomToken(8)
	if err != nil {
		return err
	}
	tmpRel := filepath.Join(parent, ".kiro-secops-tmp-"+token)
	f, err := r.root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", r.display(clean), err)
	}
	cleanupTmp := true
	defer func() {
		_ = f.Close()
		if cleanupTmp {
			_ = r.root.Remove(tmpRel)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp file for %s: %w", r.display(clean), err)
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("apply mode on temp file for %s: %w", r.display(clean), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file for %s: %w", r.display(clean), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file for %s: %w", r.display(clean), err)
	}

	if runtime.GOOS == "windows" && current.exists {
		oldRel := filepath.Join(parent, ".kiro-secops-old-"+token)
		if err := r.root.Rename(clean, oldRel); err != nil {
			return fmt.Errorf("prepare replacement of %s: %w", r.display(clean), err)
		}
		if err := r.root.Rename(tmpRel, clean); err != nil {
			_ = r.root.Rename(oldRel, clean)
			return fmt.Errorf("publish %s: %w", r.display(clean), err)
		}
		cleanupTmp = false
		if err := r.root.Remove(oldRel); err != nil {
			return fmt.Errorf("remove previous version of %s: %w", r.display(clean), err)
		}
	} else {
		if err := r.root.Rename(tmpRel, clean); err != nil {
			return fmt.Errorf("publish %s: %w", r.display(clean), err)
		}
		cleanupTmp = false
	}
	r.syncDir(parent)
	return nil
}

func (r *safeRoot) removeFile(rel string) error {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return err
	}
	snap, err := r.snapshot(clean)
	if err != nil {
		return err
	}
	if !snap.exists {
		return nil
	}
	if r.dryRun {
		fmt.Printf("  [dry-run] rm %s\n", r.display(clean))
		return nil
	}
	if err := r.root.Remove(clean); err != nil {
		return fmt.Errorf("remove %s: %w", r.display(clean), err)
	}
	r.syncDir(filepath.Dir(clean))
	return nil
}

func (r *safeRoot) restore(rel string, snap fileSnapshot) error {
	if snap.exists {
		return r.atomicWrite(rel, snap.data, snap.mode)
	}
	return r.removeFile(rel)
}

func (r *safeRoot) removeAll(rel string) error {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return err
	}
	if r.dryRun || r.root == nil {
		return nil
	}
	if err := r.validateNoSymlinks(clean, true); err != nil {
		return err
	}
	if err := r.root.RemoveAll(clean); err != nil {
		return fmt.Errorf("remove managed tree %s: %w", r.display(clean), err)
	}
	return nil
}

func (r *safeRoot) syncDir(rel string) {
	if r.root == nil {
		return
	}
	if rel == "" {
		rel = "."
	}
	f, err := r.root.Open(rel)
	if err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

// readDirNames lists the entry names of a managed directory (non-recursive),
// after the usual confinement and anti-symlink validation.
func (r *safeRoot) readDirNames(rel string) ([]string, error) {
	clean, err := r.cleanRel(rel)
	if err != nil {
		return nil, err
	}
	if r.root == nil {
		return nil, fs.ErrNotExist
	}
	if err := r.validateNoSymlinks(clean, true); err != nil {
		return nil, err
	}
	f, err := r.root.Open(clean)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", r.display(clean), err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return hex.EncodeToString(b), nil
}
