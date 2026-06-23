package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveExplorerTargetFileAndCommandLine(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	target, dir, selectFile, err := resolveExplorerTarget(`"` + exe + `" --flag`)
	if err != nil {
		t.Fatal(err)
	}
	if target != exe {
		t.Fatalf("target = %q, want %q", target, exe)
	}
	if dir != filepath.Dir(exe) {
		t.Fatalf("dir = %q, want %q", dir, filepath.Dir(exe))
	}
	if selectFile != exe {
		t.Fatalf("selectFile = %q, want %q", selectFile, exe)
	}
}

func TestResolveExplorerTargetDirectory(t *testing.T) {
	dir := t.TempDir()
	target, resolvedDir, selectFile, err := resolveExplorerTarget(dir)
	if err != nil {
		t.Fatal(err)
	}
	if target != dir {
		t.Fatalf("target = %q, want %q", target, dir)
	}
	if resolvedDir != dir {
		t.Fatalf("dir = %q, want %q", resolvedDir, dir)
	}
	if selectFile != "" {
		t.Fatalf("selectFile = %q, want empty", selectFile)
	}
}
