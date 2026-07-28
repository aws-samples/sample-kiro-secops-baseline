package app

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type embedTransform func(rel string, data []byte) ([]byte, error)

// extractTree recursively registers payload files in a managed transaction.
func extractTree(embedPrefix, destPrefix string, tx *managedTransaction) error {
	return extractTreeWithTransform(embedPrefix, destPrefix, tx, nil)
}

func extractTreeWithTransform(embedPrefix, destPrefix string, tx *managedTransaction, transform embedTransform) error {
	return fs.WalkDir(payloadFS, embedPrefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, embedPrefix+"/")
		data, err := payloadFS.ReadFile(p)
		if err != nil {
			return err
		}
		if transform != nil {
			data, err = transform(rel, data)
			if err != nil {
				return fmt.Errorf("transform %s: %w", p, err)
			}
		}
		dest := filepath.Join(destPrefix, filepath.FromSlash(rel))
		fmt.Printf("  + %s\n", tx.root.display(dest))
		return tx.Write(dest, data, 0o644)
	})
}

// copyEmbedFile registers a single payload file in the transaction.
func copyEmbedFile(embedPath, dest string, tx *managedTransaction) error {
	data, err := payloadFS.ReadFile(embedPath)
	if err != nil {
		return err
	}
	fmt.Printf("  + %s\n", tx.root.display(dest))
	return tx.Write(dest, data, 0o644)
}

// copySelf registers the binary itself in the transaction.
func copySelf(dest string, tx *managedTransaction) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	fmt.Printf("  + %s (binary)\n", tx.root.display(dest))
	return tx.Write(dest, data, 0o755)
}

// walkEmbedFiles calls fn(relPath) for each file (non-directory) under embedPrefix.
func walkEmbedFiles(embedPrefix string, fn func(rel string)) error {
	return fs.WalkDir(payloadFS, embedPrefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fn(strings.TrimPrefix(p, embedPrefix+"/"))
		return nil
	})
}
