package harness

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stopCheck runs .claude/hooks/stop-check.sh against a scratch repository in
// which `make` is a fake whose exit status the test controls and whose runs
// it counts.
type stopCheck struct {
	t      *testing.T
	repo   string
	bin    string
	script string
}

func newStopCheck(t *testing.T, withIndex bool) *stopCheck {
	t.Helper()
	script, err := filepath.Abs("../../.claude/hooks/stop-check.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := &stopCheck{t: t, repo: t.TempDir(), bin: t.TempDir(), script: script}

	s.git("init", "--quiet")
	s.write("a.txt", "a")
	if withIndex {
		s.git("add", "a.txt")
	}

	fake := "#!/bin/sh\n" +
		`echo run >> "` + filepath.Join(s.bin, "runs") + "\"\n" +
		`exit "$(cat "` + filepath.Join(s.bin, "status") + "\")\"\n"
	if err := os.WriteFile(filepath.Join(s.bin, "make"), []byte(fake), 0o755); err != nil { //nolint:gosec // The fake must be executable.
		t.Fatal(err)
	}
	s.setGate(0)
	return s
}

func (s *stopCheck) git(args ...string) {
	s.t.Helper()
	cmd := exec.CommandContext(s.t.Context(), "git", args...) //nolint:gosec // G204: the arguments are the test's own.
	cmd.Dir = s.repo
	if out, err := cmd.CombinedOutput(); err != nil {
		s.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (s *stopCheck) write(name, content string) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.repo, name), []byte(content), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// setGate sets the exit status of the fake `make check`.
func (s *stopCheck) setGate(status int) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.bin, "status"), []byte(strconv.Itoa(status)), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// runs reports how many times the gate has run.
func (s *stopCheck) runs() int {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(s.bin, "runs"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		s.t.Fatal(err)
	}
	return strings.Count(string(b), "run")
}

// stop runs the hook as Claude Code would and returns its exit status and
// standard error.
func (s *stopCheck) stop(input string) (int, string) {
	s.t.Helper()
	cmd := exec.CommandContext(s.t.Context(), "bash", s.script) //nolint:gosec // G204: the script is the repository's own hook.
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(),
		"CLAUDE_PROJECT_DIR="+s.repo,
		"PATH="+s.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), stderr.String()
	}
	if err != nil {
		s.t.Fatal(err)
	}
	return 0, stderr.String()
}

func TestStopCheckPassIsCached(t *testing.T) {
	t.Parallel()
	s := newStopCheck(t, true)

	if code, _ := s.stop("{}"); code != 0 {
		t.Fatalf("first stop exit = %d, want 0", code)
	}
	if code, _ := s.stop("{}"); code != 0 {
		t.Errorf("second stop exit = %d, want 0", code)
	}
	if got := s.runs(); got != 1 {
		t.Errorf("gate runs = %d, want 1: an unchanged tree that passed is not checked again", got)
	}

	s.write("a.txt", "changed")
	s.stop("{}")
	if got := s.runs(); got != 2 {
		t.Errorf("gate runs after an edit = %d, want 2", got)
	}
}

func TestStopCheckFailureIsReportedOncePerTree(t *testing.T) {
	t.Parallel()
	s := newStopCheck(t, true)
	s.setGate(1)

	code, stderr := s.stop("{}")
	if code != 2 {
		t.Fatalf("stop on a failing gate exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "make check failed") {
		t.Errorf("stderr = %q, want it to report the failure", stderr)
	}

	if code, _ := s.stop(`{"stop_hook_active":true}`); code != 0 {
		t.Errorf("second stop on the same tree exit = %d, want 0 so Claude is not trapped", code)
	}
	if got := s.runs(); got != 1 {
		t.Errorf("gate runs = %d, want 1", got)
	}

	s.write("a.txt", "fixed")
	s.setGate(0)
	if code, _ := s.stop("{}"); code != 0 {
		t.Errorf("stop after a fix exit = %d, want 0", code)
	}
	if got := s.runs(); got != 2 {
		t.Errorf("gate runs after an edit = %d, want 2", got)
	}
}

// A repository with no index cannot be fingerprinted. The hook must then
// check every time rather than cache a result it cannot key, and fall back on
// stop_hook_active to avoid a loop.
func TestStopCheckWithoutFingerprintAlwaysChecks(t *testing.T) {
	t.Parallel()
	s := newStopCheck(t, false)

	s.stop("{}")
	s.stop("{}")
	if got := s.runs(); got != 2 {
		t.Errorf("gate runs = %d, want 2: nothing may be cached without a fingerprint", got)
	}

	s.setGate(1)
	if code, _ := s.stop("{}"); code != 2 {
		t.Errorf("stop on a failing gate exit = %d, want 2", code)
	}
	if code, _ := s.stop(`{"stop_hook_active":true}`); code != 0 {
		t.Errorf("stop with stop_hook_active exit = %d, want 0", code)
	}
	if got := s.runs(); got != 3 {
		t.Errorf("gate runs = %d, want 3: stop_hook_active skips the check", got)
	}
}
