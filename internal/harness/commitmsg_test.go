package harness

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCheckCommitMsg runs scripts/check-commit-msg.sh, which once let
// "feat: A new endpoint" through because it only rejected a capital followed
// by a lower-case letter, and later refused every pull request Dependabot
// opened, whose titles read "build: Bump …".
func TestCheckCommitMsg(t *testing.T) {
	t.Parallel()
	script, err := filepath.Abs("../../scripts/check-commit-msg.sh")
	if err != nil {
		t.Fatal(err)
	}

	const longDependabot = "build: Bump golang.org/x/exp from 0.0.0-20250620022241-b7579e27df2b " +
		"to 0.0.0-20260101000000-0123456789ab in /tools"
	tests := []struct {
		header     string
		dependabot bool
		want       bool
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
		{header: "build: Bump github.com/google/cel-go from 0.28.0 to 0.29.0 in /tools", want: false},
		{header: longDependabot, want: false},

		// Dependabot's own pull requests: its case and its lengths, but
		// still a known type and no trailing period.
		{header: "build: Bump github.com/google/cel-go from 0.28.0 to 0.29.0 in /tools", dependabot: true, want: true},
		{header: "ci: Bump the actions group with 2 updates", dependabot: true, want: true},
		{header: "build(deps): Bump google.golang.org/grpc from 1.80.0 to 1.83.2", dependabot: true, want: true},
		{header: "build: bump google.golang.org/grpc from 1.80.0 to 1.83.2 in /tools", dependabot: true, want: true},
		{header: longDependabot, dependabot: true, want: true},
		{header: "Bump github.com/google/cel-go from 0.28.0 to 0.29.0", dependabot: true, want: false},
		{header: "chores: Bump github.com/google/cel-go from 0.28.0 to 0.29.0", dependabot: true, want: false},
		{header: "build: Bump github.com/google/cel-go.", dependabot: true, want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/dependabot=%t", tt.header, tt.dependabot), func(t *testing.T) {
			t.Parallel()
			msg := filepath.Join(t.TempDir(), "msg")
			if err := os.WriteFile(msg, []byte(tt.header+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{script}
			if tt.dependabot {
				args = append(args, "--dependabot")
			}
			args = append(args, msg)
			err := exec.CommandContext(t.Context(), "bash", args...).Run() //nolint:gosec // G204: the script is the repository's own.
			got := err == nil
			if exit, ok := errors.AsType[*exec.ExitError](err); err != nil && !ok {
				t.Fatalf("running the script: %v", err)
			} else if ok && exit.ExitCode() != 1 {
				t.Fatalf("check-commit-msg.sh exit = %d, want 0 or 1", exit.ExitCode())
			}
			if got != tt.want {
				t.Errorf("check-commit-msg.sh(dependabot=%t, %q) accepted = %v, want %v", tt.dependabot, tt.header, got, tt.want)
			}
		})
	}
}
