package harness

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCheckCommitMsg runs scripts/check-commit-msg.sh, which once let
// "feat: A new endpoint" through because it only rejected a capital followed
// by a lower-case letter.
func TestCheckCommitMsg(t *testing.T) {
	t.Parallel()
	script, err := filepath.Abs("../../scripts/check-commit-msg.sh")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		header string
		want   bool
	}{
		{header: "feat: add discovery", want: true},
		{header: "fix(token)!: reject reused codes", want: true},
		{header: "feat: add JWKS rotation", want: true},
		{header: "docs: OAuth error formats", want: true},
		{header: "fixup! feat: add discovery", want: true},
		{header: "feat: Add discovery", want: false},
		{header: "feat: A new endpoint", want: false},
		{header: "feat: I added discovery", want: false},
		{header: "feat: add discovery.", want: false},
		{header: "Feat: add discovery", want: false},
		{header: "add discovery", want: false},
		{header: "feat: this header runs well past the seventy-two character limit on headers", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			t.Parallel()
			msg := filepath.Join(t.TempDir(), "msg")
			if err := os.WriteFile(msg, []byte(tt.header+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := exec.CommandContext(t.Context(), "bash", script, msg).Run() //nolint:gosec // G204: the script is the repository's own.
			got := err == nil
			if exit, ok := errors.AsType[*exec.ExitError](err); err != nil && !ok {
				t.Fatalf("running the script: %v", err)
			} else if ok && exit.ExitCode() != 1 {
				t.Fatalf("check-commit-msg.sh exit = %d, want 0 or 1", exit.ExitCode())
			}
			if got != tt.want {
				t.Errorf("check-commit-msg.sh(%q) accepted = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}
