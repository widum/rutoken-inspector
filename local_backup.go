package main

// Backup of existing local CSP file containers for the account owner.
// This never reads a physical Rutoken or tries to bypass hardware flags.
import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func validateLocalCSPSource(src string) error {
	root, err := cspDestination()
	if err != nil {
		return err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Dir(srcAbs), rootAbs) || !numberedContainer.MatchString(filepath.Base(srcAbs)) {
		return fmt.Errorf("резервная копия доступна только для папки NNNN.000 в %s", root)
	}
	if _, err := quickSourcesDir(srcAbs); err != nil {
		return err
	}
	return nil
}
func writeLocalCSPBackup(src, dest string) (err error) {
	if err = validateLocalCSPSource(src); err != nil {
		return err
	}
	plan, err := quickSourcesDir(src)
	if err != nil {
		return err
	}
	c := plan.Candidates[0]
	folder := filepath.Base(src)
	// refuse overwriting existing files (avoid accidental disclosure or corruption)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(dest)
		}
	}()
	zw := zip.NewWriter(out)
	add := func(entry quickEntry, name string) error {
		rc, e := entry.Open()
		if e != nil {
			return e
		}
		defer rc.Close()
		w, e := zw.Create(folder + "/" + name)
		if e != nil {
			return e
		}
		n, e := io.Copy(w, io.LimitReader(rc, maxQuickFile+1))
		if e != nil {
			return e
		}
		if n != entry.Size || n > maxQuickFile {
			return fmt.Errorf("изменение/недопустимый размер %s", name)
		}
		return nil
	}
	for _, n := range sixCSPFiles {
		if err = add(c.Keys[n], n); err != nil {
			_ = zw.Close()
			return err
		}
	}
	if c.Cert != nil {
		if err = add(*c.Cert, c.Cert.Name); err != nil {
			_ = zw.Close()
			return err
		}
	}
	if err = zw.Close(); err != nil {
		return err
	}
	return out.Sync()
}