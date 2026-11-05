// Repocheck enforces the repository conventions that no linter covers:
//
//   - every requirement ID defined under docs/requirements is cited, in a
//     comment of at least one test file, and every requirement ID a test
//     cites is defined;
//   - every to-do comment in Go code names its issue, as in TODO(#123).
//
// It prints one line per violation and exits with status 1 if there are any.
//
// Usage:
//
//	go run ./internal/cmd/repocheck
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
)

var (
	reqID = regexp.MustCompile(`\bREQ-[A-Z0-9]+(?:-[A-Z0-9]+)*\b`)
	todo  = regexp.MustCompile(`\bTODO\b(\(#[0-9]+\))?`)
)

func main() {
	problems, err := check(os.DirFS("."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "repocheck: %v\n", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
}

// check walks fsys and returns its violations, sorted.
func check(fsys fs.FS) ([]string, error) {
	defined := make(map[string]string) // requirement ID → defining file
	cited := make(map[string]string)   // requirement ID → first citing test
	var problems []string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasPrefix(path, "docs/requirements/") && strings.HasSuffix(path, ".md"):
			src, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			record(defined, path, src)
		case strings.HasSuffix(path, ".go"):
			src, err := fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			var citing map[string]string
			if strings.HasSuffix(path, "_test.go") {
				citing = cited
			}
			found, err := comments(path, src, citing)
			if err != nil {
				return err
			}
			problems = append(problems, found...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for id, path := range defined {
		if _, ok := cited[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not cited by any test", path, id))
		}
	}
	for id, path := range cited {
		if _, ok := defined[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %s is not defined under docs/requirements", path, id))
		}
	}
	slices.Sort(problems)
	return problems, nil
}

// skipDir reports whether a directory holds nothing the conventions apply
// to: hidden directories, test fixtures and vendored code.
func skipDir(name string) bool {
	return strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor"
}

// record notes each requirement ID in src against path, keeping the first
// path seen.
func record(ids map[string]string, path string, src []byte) {
	for _, id := range reqID.FindAllString(string(src), -1) {
		if _, ok := ids[id]; !ok {
			ids[id] = path
		}
	}
}

// comments checks the comments of a Go file. It returns a violation for each
// to-do comment that does not name an issue and, if cited is non-nil, records
// the requirement IDs the comments mention. String literals are not comments,
// so test fixtures cannot cite a requirement by accident.
func comments(path string, src []byte, cited map[string]string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, group := range f.Comments {
		for _, c := range group.List {
			if cited != nil {
				record(cited, path, []byte(c.Text))
			}
			for _, m := range todo.FindAllStringSubmatch(c.Text, -1) {
				if m[1] == "" {
					problems = append(problems, fmt.Sprintf("%s: TODO must name its issue, as in TODO(#123)", fset.Position(c.Pos())))
				}
			}
		}
	}
	return problems, nil
}
