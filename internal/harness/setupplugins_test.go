package harness

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fakeClaude is a `claude` that logs each call, with the value of
// CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, to calls. marketplace add keeps a
// copy of the marketplace under marketplaces/, named by the repository's
// second half unless names maps the repository to another, and rewrites the
// settings file as the real one does. An install fails for a plugin listed in
// fail, and changes the copy of the marketplace named in moves, as a refresh
// would.
const fakeClaude = `#!/bin/sh
bin=$(dirname "$0")
printf '%s %s\n' "${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC-unset}" "$*" >>"$bin/calls"
case "$2 $3" in
"marketplace add")
	name=$(awk -v r="$4" '$1 == r { print $2 }' "$bin/names" 2>/dev/null)
	name=${name:-${4#*/}}
	mkdir -p "$bin/marketplaces/$name"
	echo v1 >"$bin/marketplaces/$name/catalog"
	echo '{}' >.claude/settings.json
	echo "Adding marketplace..."
	printf '{"marketplace":"%s","message":"Added %s"}\n' "$name" "$name"
	;;
"marketplace list")
	sep=
	printf '['
	for d in "$bin"/marketplaces/*; do
		[ -d "$d" ] || continue
		printf '%s{"name":"%s","installLocation":"%s"}' "$sep" "$(basename "$d")" "$d"
		sep=,
	done
	printf ']\n'
	;;
"install "*)
	echo '{}' >.claude/settings.json
	if grep -qx "$3" "$bin/fail" 2>/dev/null; then
		echo "install failed" >&2
		exit 1
	fi
	if [ -f "$bin/moves" ]; then
		echo v2 >"$bin/marketplaces/$(cat "$bin/moves")/catalog"
	fi
	;;
esac
`

// setupSettings declares a frozen marketplace and one that updates itself,
// and enables a plugin from each; c@own is disabled.
const setupSettings = `{
  "extraKnownMarketplaces": {
    "official": {
      "source": { "source": "github", "repo": "o/official" },
      "autoUpdate": false
    },
    "own": {
      "source": { "source": "github", "repo": "o/own" },
      "autoUpdate": true
    }
  },
  "enabledPlugins": { "a@official": true, "b@own": true, "c@own": false }
}
`

// setupPlugins runs scripts/setup-plugins.sh in a scratch repository whose
// settings are the given file, with the fake claude first on PATH. files are
// written to the fake's directory first. It returns the exit status, the
// fake's calls and standard error, and fails the test unless the settings
// file is restored byte for byte.
func setupPlugins(t *testing.T, settings string, files map[string]string) (code int, calls []string, stderr string) {
	t.Helper()
	script, err := filepath.Abs("../../scripts/setup-plugins.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo, bin := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(repo, ".claude", "settings.json")
	if err := os.WriteFile(settingsPath, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(fakeClaude), 0o755); err != nil { //nolint:gosec // The fake must be executable.
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.CommandContext(t.Context(), "bash", script) //nolint:gosec // G204: the script is the repository's own.
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=",
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(settingsPath) //nolint:gosec // G304: a path in the test's own temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(settings, string(got)); diff != "" {
		t.Errorf("settings after setup-plugins.sh differ (-before +after):\n%s", diff)
	}

	log, err := os.ReadFile(filepath.Join(bin, "calls")) //nolint:gosec // G304: a path in the test's own temporary directory.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if s := strings.TrimSuffix(string(log), "\n"); s != "" {
		calls = strings.Split(s, "\n")
	}
	return code, calls, errOut.String()
}

func TestSetupPlugins(t *testing.T) {
	t.Parallel()
	added := []string{
		"1 plugin marketplace add o/official --scope project --json",
		"1 plugin marketplace add o/own --scope project --json",
		"1 plugin marketplace update own",
	}
	installed := []string{
		"1 plugin marketplace list --json",
		"1 plugin install a@official --scope project",
		"1 plugin install b@own --scope project",
		"1 plugin marketplace list --json",
	}
	tests := []struct {
		name       string
		settings   string
		files      map[string]string
		wantCode   int
		wantCalls  []string
		wantStderr string
	}{
		{
			name:      "adds the marketplaces, updates the one with autoUpdate on, installs the enabled plugins",
			settings:  setupSettings,
			wantCalls: append(append([]string{}, added...), installed...),
		},
		{
			name:     "no marketplaces declared",
			settings: `{"enabledPlugins": {"a@official": true}}`,
			wantCalls: []string{
				"1 plugin marketplace list --json",
				"1 plugin install a@official --scope project",
				"1 plugin marketplace list --json",
			},
		},
		{
			name:       "a marketplace added under another name than its key",
			settings:   setupSettings,
			files:      map[string]string{"names": "o/own other\n"},
			wantCode:   1,
			wantCalls:  added[:2],
			wantStderr: "o/own is declared as own but was added as other",
		},
		{
			name:       "an install that changes a frozen marketplace",
			settings:   setupSettings,
			files:      map[string]string{"moves": "official"},
			wantCode:   1,
			wantCalls:  append(append([]string{}, added...), installed...),
			wantStderr: "an install changed a marketplace with autoUpdate off: official",
		},
		{
			name:       "an install that fails",
			settings:   setupSettings,
			files:      map[string]string{"fail": "a@official\n"},
			wantCode:   1,
			wantCalls:  append(append([]string{}, added...), installed[:2]...),
			wantStderr: "install failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, calls, stderr := setupPlugins(t, tt.settings, tt.files)
			if code != tt.wantCode {
				t.Errorf("setup-plugins.sh exit = %d, want %d; stderr:\n%s", code, tt.wantCode, stderr)
			}
			if diff := cmp.Diff(tt.wantCalls, calls); diff != "" {
				t.Errorf("claude calls differ (-want +got):\n%s", diff)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
		})
	}
}

// A declaration the script cannot pass on as written stops it before any
// claude command runs.
func TestSetupPluginsRefusesDeclarations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		settings   string
		wantStderr string
	}{
		{
			name:       "a url source",
			settings:   `{"extraKnownMarketplaces": {"m": {"source": {"source": "url", "url": "https://example.com/m.json"}}}}`,
			wantStderr: "m: only a GitHub marketplace named by owner/repo alone can be added",
		},
		{
			name:       "a GitHub source pinned to a ref",
			settings:   `{"extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "o/m", "ref": "v1"}}}}`,
			wantStderr: "m: only a GitHub marketplace",
		},
		{
			name:       "a repo that is not owner/repo",
			settings:   `{"extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "-x/y"}}}}`,
			wantStderr: "m: only a GitHub marketplace",
		},
		{
			name:       "a repo that would glob",
			settings:   `{"extraKnownMarketplaces": {"m": {"source": {"source": "github", "repo": "*"}}}}`,
			wantStderr: "m: only a GitHub marketplace",
		},
		{
			name:       "a plugin not named plugin@marketplace",
			settings:   `{"enabledPlugins": {"a b@m": true}}`,
			wantStderr: "a b@m: not a plugin@marketplace name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, calls, stderr := setupPlugins(t, tt.settings, nil)
			if code == 0 {
				t.Errorf("setup-plugins.sh exit = 0, want nonzero")
			}
			if len(calls) != 0 {
				t.Errorf("claude calls = %q, want none", calls)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
		})
	}
}
