package tables

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNumericTablesRankByPosition(t *testing.T) {
	s, err := Parse("100,main,1000", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[int]int{100: 0, 254: 1, 1000: 2} {
		got, ok := s.Rank(table)
		if !ok || got != want {
			t.Errorf("Rank(%d) = %d, %v; want %d, true", table, got, ok, want)
		}
	}
	if _, ok := s.Rank(200); ok {
		t.Error("unlisted table 200 is monitored")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNamesResolveFromRtTablesFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc/iproute2/rt_tables"),
		"# comment\n0x64 bird\n200\tvrf-blue # trailing\nnot a line\n")
	writeFile(t, filepath.Join(root, "etc/iproute2/rt_tables.d/x.conf"), "300 vrf-blue\n1000 big\n")
	writeFile(t, filepath.Join(root, "usr/share/iproute2/rt_tables"), "400 fallback\n")

	s, err := Parse("bird vrf-blue,\tbig  fallback", root)
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[int]int{100: 0, 200: 1, 1000: 2, 400: 3} {
		got, ok := s.Rank(table)
		if !ok || got != want {
			t.Errorf("Rank(%d) = %d, %v; want %d, true", table, got, ok, want)
		}
	}
	if _, ok := s.Rank(300); ok {
		t.Error("later file overrode earlier file for vrf-blue")
	}
}

func TestAllMatchesUnlistedTablesRankedLast(t *testing.T) {
	s, err := Parse("all 100 main 100", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[int]int{100: 0, 254: 1, 200: 2, 1000: 2, 255: 2} {
		got, ok := s.Rank(table)
		if !ok || got != want {
			t.Errorf("Rank(%d) = %d, %v; want %d, true", table, got, ok, want)
		}
	}
}

func TestEmptyMeansMain(t *testing.T) {
	s, err := Parse("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := s.Rank(254); !ok || r != 0 {
		t.Errorf("Rank(main) = %d, %v; want 0, true", r, ok)
	}
}

func TestInvalidSelectionsAreRejected(t *testing.T) {
	for _, in := range []string{"nosuchtable", "0", "main,0x0", ",", " , \t"} {
		if _, err := Parse(in, t.TempDir()); err == nil {
			t.Errorf("Parse(%q) succeeded; want error", in)
		}
	}
}
