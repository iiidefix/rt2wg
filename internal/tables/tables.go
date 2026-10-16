// Package tables parses WG_ROUTE_TABLES into the set of monitored tables and
// their table ranks.
package tables

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Set is an ordered selection of monitored tables. A lower rank is preferred.
type Set struct {
	ranks  map[int]int
	listed []int
	all    bool // unlisted tables are monitored, ranked after listed ones
}

// Parse parses a WG_ROUTE_TABLES value. root is the filesystem root used to
// find iproute2 rt_tables files ("/" in production).
func Parse(s string, root string) (*Set, error) {
	if strings.TrimSpace(s) == "" {
		s = "main"
	}
	set := &Set{ranks: map[int]int{}}
	r := &resolver{root: root}
	for _, tok := range strings.FieldsFunc(s, isSep) {
		if tok == "all" {
			set.all = true
			continue
		}
		table, err := r.resolve(tok)
		if err != nil {
			return nil, err
		}
		if table == 0 {
			return nil, fmt.Errorf("routing table %q: table 0 is not allowed", tok)
		}
		if _, dup := set.ranks[table]; dup {
			continue
		}
		set.ranks[table] = len(set.listed)
		set.listed = append(set.listed, table)
	}
	if len(set.listed) == 0 && !set.all {
		return nil, errors.New("no routing tables selected")
	}
	return set, nil
}

func isSep(r rune) bool { return r == ',' || r == ' ' || r == '\t' }

// Rank reports whether table is monitored and, if so, its table rank.
func (s *Set) Rank(table int) (int, bool) {
	if r, ok := s.ranks[table]; ok {
		return r, true
	}
	return len(s.listed), s.all
}

var builtin = map[string]int{"main": 254, "local": 255, "default": 253}

// nameFiles are the iproute2 table name files, earliest wins. Entries ending
// in "/" are directories whose *.conf files are read in lexical order.
var nameFiles = []string{
	"etc/iproute2/rt_tables",
	"etc/iproute2/rt_tables.d/",
	"usr/share/iproute2/rt_tables",
	"usr/share/iproute2/rt_tables.d/",
	"usr/lib/iproute2/rt_tables",
}

// resolver maps table tokens to ids, reading name files only when a
// non-builtin name needs resolving.
type resolver struct {
	root  string
	names map[string]int
}

func (r *resolver) resolve(tok string) (int, error) {
	if id, err := strconv.ParseUint(tok, 0, 32); err == nil {
		return int(id), nil
	}
	if id, ok := builtin[tok]; ok {
		return id, nil
	}
	if r.names == nil {
		r.names = loadNames(r.root)
	}
	if id, ok := r.names[tok]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown routing table %q", tok)
}

func loadNames(root string) map[string]int {
	names := map[string]int{}
	for _, f := range nameFiles {
		path := filepath.Join(root, f)
		if !strings.HasSuffix(f, "/") {
			readNameFile(path, names)
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(path, "*.conf"))
		sort.Strings(matches)
		for _, m := range matches {
			readNameFile(m, names)
		}
	}
	return names
}

func readNameFile(path string, names map[string]int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 0, 32)
		if err != nil {
			continue
		}
		if _, seen := names[fields[1]]; !seen {
			names[fields[1]] = int(id)
		}
	}
}

// String lists the monitored tables by id in rank order, for logging.
func (s *Set) String() string {
	parts := make([]string, 0, len(s.listed)+1)
	for _, t := range s.listed {
		parts = append(parts, strconv.Itoa(t))
	}
	if s.all {
		parts = append(parts, "all")
	}
	return strings.Join(parts, ",")
}
