// Package harness tests the harness scripts that have failed before: the Stop
// hook in .claude/hooks, and the commit message check and the plugin setup in
// scripts. It has no code of its own: the scripts are the subject, and Go's
// test runner is what keeps them honest.
package harness
