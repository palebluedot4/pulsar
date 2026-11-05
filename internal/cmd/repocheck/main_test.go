package main

import (
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

func TestCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files fstest.MapFS
		want  []string
	}{
		{
			name: "requirement cited by a test",
			files: fstest.MapFS{
				"docs/requirements/pkce.md": file("- REQ-PKCE-1: The server MUST reject a mismatched verifier."),
				"internal/oidc/pkce_test.go": file(
					"package oidc\n\n// REQ-PKCE-1\nfunc TestVerifier() {}\n"),
			},
			want: nil,
		},
		{
			name: "requirement without a test",
			files: fstest.MapFS{
				"docs/requirements/pkce.md": file("- REQ-PKCE-1: …\n- REQ-PKCE-2: …"),
				"internal/oidc/pkce_test.go": file(
					"package oidc\n\n// REQ-PKCE-1\nfunc TestVerifier() {}\n"),
			},
			want: []string{"docs/requirements/pkce.md: REQ-PKCE-2 is not cited by any test"},
		},
		{
			name: "test cites an undefined requirement",
			files: fstest.MapFS{
				"internal/oidc/pkce_test.go": file(
					"package oidc\n\n// REQ-PKCE-9\nfunc TestVerifier() {}\n"),
			},
			want: []string{"internal/oidc/pkce_test.go: REQ-PKCE-9 is not defined under docs/requirements"},
		},
		{
			name: "a citation outside tests does not count",
			files: fstest.MapFS{
				"docs/requirements/pkce.md": file("- REQ-PKCE-1: …"),
				"internal/oidc/pkce.go":     file("package oidc\n\n// REQ-PKCE-1\nfunc verify() {}\n"),
			},
			want: []string{"docs/requirements/pkce.md: REQ-PKCE-1 is not cited by any test"},
		},
		{
			name: "a string literal in a test does not cite",
			files: fstest.MapFS{
				"docs/requirements/pkce.md": file("- REQ-PKCE-1: …"),
				"internal/oidc/pkce_test.go": file(
					"package oidc\n\nvar fixture = \"REQ-PKCE-1\"\n"),
			},
			want: []string{"docs/requirements/pkce.md: REQ-PKCE-1 is not cited by any test"},
		},
		{
			name: "to-do comments",
			files: fstest.MapFS{
				"a.go": file("package a\n\n// TODO(#12): fine.\n// TODO: no issue.\n/* TODO(alice) */\nvar s = \"TODO\"\n"),
			},
			want: []string{
				"a.go:4:1: TODO must name its issue, as in TODO(#123)",
				"a.go:5:1: TODO must name its issue, as in TODO(#123)",
			},
		},
		{
			name: "hidden directories and fixtures are skipped",
			files: fstest.MapFS{
				".claude/x.go":       file("package x\n\n// TODO: ignored.\n"),
				"pkg/testdata/y.go":  file("package y\n\n// TODO: ignored.\n"),
				"vendor/v/v.go":      file("package v\n\n// TODO: ignored.\n"),
				"docs/other/note.md": file("REQ-NOT-A-DEFINITION"),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := check(tt.files)
			if err != nil {
				t.Fatalf("check() error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("check() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func file(s string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(s)}
}
