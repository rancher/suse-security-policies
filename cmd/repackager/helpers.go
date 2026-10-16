package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// run returns the stdout of a tool. It also returns the stdout of a tool
// that failed, because sbom-utility prints its findings there. run is a
// variable because the tests replace it with a fake (see fake_test.go), so
// that no real tool runs. The tools must be on the PATH.
var run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	logf("+ %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(stderr.String())
		// The callers match the error text, so it holds only the stderr of the
		// tool and not the args. nothingSigned reads the exit code through %w.
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, tail[max(0, len(tail)-2048):])
	}
	return stdout.Bytes(), nil
}

func kwctl(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "kwctl", args...) }

func cosign(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "cosign", args...) }

func github(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "gh", args...) }

func sbomUtility(ctx context.Context, args ...string) ([]byte, error) {
	return run(ctx, "sbom-utility", args...)
}

func githubRelease(ctx context.Context, args ...string) ([]byte, error) {
	return github(ctx, append([]string{"release"}, args...)...)
}

// githubAPI passes --hostname, so that GH_HOST cannot change the host.
func githubAPI(ctx context.Context, args ...string) ([]byte, error) {
	return github(ctx, append([]string{"api", "--hostname", "github.com"}, args...)...)
}

func readJSON(path string) (any, error) { return decode(os.ReadFile(path)) }

func decode(data []byte, err error) (any, error) {
	var v any
	if err == nil {
		err = json.Unmarshal(data, &v)
	}
	return v, err
}

// ghExists treats only "HTTP 404" as a missing path. Any other failure of gh
// is an error, so that a bad token does not look like a missing release.
func ghExists(ctx context.Context, path string) (bool, error) {
	_, err := githubAPI(ctx, path)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		return false, nil
	}
	return err == nil, err
}

func get(v any, path ...string) any {
	for _, p := range path {
		m, _ := v.(map[string]any)
		v = m[p]
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := get(v, path...).(string)
	return s
}

func list(v any, path ...string) []any {
	l, _ := get(v, path...).([]any)
	return l
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), err
}
