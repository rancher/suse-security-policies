package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "write the golden files in testdata again")

// rule gives the result of the first call whose command line starts with
// prefix. In the command line, the work directory is "$WORK".
type rule struct {
	prefix string
	out    string
	fn     func(work string) string // if not nil, gives the output at call time, in place of out
	err    string                   // if not empty, the call fails with this message
	write  string                   // if not empty, written to the path after -o, --output or --bundle
	once   bool                     // if true, the rule is removed after its first match
}

type fake struct {
	t     *testing.T
	work  string
	rules []rule
	calls []string
}

// newFake replaces run until the test ends. It also discards the log and
// clears the GitHub Actions files, so that a test run in a workflow does not
// write to them. It sets GITHUB_WORKFLOW_REF to the workflow of this
// repository, so that the signing identity does not depend on the workflow
// that runs the test.
func newFake(t *testing.T, work string, rules ...rule) *fake {
	f := &fake{t: t, work: work, rules: rules}
	oldRun, oldLog := run, logOut
	run, logOut = f.run, io.Discard
	t.Cleanup(func() { run, logOut = oldRun, oldLog })
	t.Setenv("GITHUB_OUTPUT", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	t.Setenv("GITHUB_WORKFLOW_REF", "rancher/suse-security-policies/.github/workflows/sync-upstream-releases.yaml@refs/heads/main")
	return f
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	if f.work != "" {
		line = strings.ReplaceAll(line, f.work, "$WORK")
	}
	f.calls = append(f.calls, line)
	i := slices.IndexFunc(f.rules, func(r rule) bool { return strings.HasPrefix(line, r.prefix) })
	if i < 0 {
		f.t.Errorf("no rule matches the call %q", line)
		return nil, errors.New("no rule matches the call")
	}
	r := f.rules[i]
	if r.once {
		f.rules = slices.Delete(f.rules, i, i+1)
	}
	if r.write != "" {
		for k, a := range args[:len(args)-1] {
			if a == "-o" || a == "--output" || a == "--bundle" {
				if err := os.WriteFile(args[k+1], []byte(r.write), 0o644); err != nil {
					f.t.Fatal(err)
				}
			}
		}
	}
	out := r.out
	if r.fn != nil {
		out = r.fn(f.work)
	}
	if r.err != "" {
		return []byte(out), errors.New(r.err)
	}
	return []byte(out), nil
}

// execute runs the command line and returns what it wrote to stdout.
func execute(t *testing.T, args ...string) (string, error) {
	var out bytes.Buffer
	old := cmdOut
	cmdOut = &out
	t.Cleanup(func() { cmdOut = old })
	root := newRootCommand()
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v. Run go test -update to write the golden file", err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("the output is not equal to %s. If the change is correct, run go test -update (-want +got):\n%s", path, diff)
	}
}
