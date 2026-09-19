package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func installCLI(args []string, out io.Writer) error {
	prefix := flagValue(args, "--prefix", "/usr/local")
	dest := filepath.Join(prefix, "bin", "shukractl")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	src, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	fmt.Fprintf(out, "installed %s\n", dest)
	fmt.Fprintln(out, "Run: shukractl status")
	return nil
}
