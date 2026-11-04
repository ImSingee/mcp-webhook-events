package sqlitedb

import (
	"context"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestWellFormed(t *testing.T) {
	in := []string{"PATH=/bin", "fragment/with/no/equals", "", "EMPTY=", "A=b=c"}
	want := []string{"PATH=/bin", "EMPTY=", "A=b=c"}
	if got := wellFormed(in); !slices.Equal(got, want) {
		t.Fatalf("wellFormed = %q, want %q", got, want)
	}
}

func TestOpenSetsPragmas(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var fk int
	var mode string
	db.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if fk != 1 || mode != "wal" {
		t.Fatalf("foreign_keys=%d journal_mode=%s", fk, mode)
	}
}

// Every SQLite open goes through this package, so libc's environment is
// cleaned first: no other package imports modernc's driver or libc.
func TestOnlyThisPackageReachesSQLite(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	self := filepath.Join(root, "internal", "sqlitedb")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || path == self) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.HasPrefix(p, "modernc.org/sqlite") || p == "modernc.org/libc" {
				t.Errorf("%s imports %s; go through internal/sqlitedb", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
