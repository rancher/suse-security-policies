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
	"regexp"
	"slices"
	"strings"
	"time"
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

// sleep is a variable because the tests replace it, so that no test waits.
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var retryWaits = []time.Duration{2 * time.Second, 8 * time.Second}

// retryRead runs a tool that only reads, and tries again after a failure
// for which permanent returns false. Only reads come here: a write that failed
// can still have changed the registry or the release, and the releases are
// immutable, so a person must look at a failed write.
func retryRead(ctx context.Context, permanent func(error) bool, name string, args ...string) ([]byte, error) {
	out, err := run(ctx, name, args...)
	for _, wait := range retryWaits {
		if err == nil || permanent(err) || ctx.Err() != nil {
			break
		}
		logf("::warning::%s", escapeData(fmt.Sprintf("%s %s failed: %v. The run tries again in %s.", name, strings.Join(args, " "), err, wait)))
		if sleep(ctx, wait) != nil {
			break
		}
		out, err = run(ctx, name, args...)
	}
	return out, err
}

func kwctl(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "kwctl", args...) }

// kwctlRead is for kwctl pull and kwctl digest of the policy id. A tag that
// is not in the registry stays missing on the next try.
func kwctlRead(ctx context.Context, id string, args ...string) ([]byte, error) {
	return retryRead(ctx, func(err error) bool { return tagMissing(err, id) }, "kwctl", args...)
}

// tagMissing removes the policy id from the error first. The id comes from
// upstream, so it must not make the match.
func tagMissing(err error, id string) bool {
	return notFoundPattern.MatchString(strings.ReplaceAll(err.Error(), id, ""))
}

func cosign(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "cosign", args...) }

// cosignVerify tries again after every error except nothingSigned, because
// the error of cosign does not tell a bad signature from a registry or a
// Rekor error. Thus a bad signature fails three times.
func cosignVerify(ctx context.Context, args ...string) ([]byte, error) {
	return retryRead(ctx, nothingSigned, "cosign", args...)
}

func github(ctx context.Context, args ...string) ([]byte, error) { return run(ctx, "gh", args...) }

func sbomUtility(ctx context.Context, args ...string) ([]byte, error) {
	return run(ctx, "sbom-utility", args...)
}

// gh api prints "Not Found (HTTP 404)" or "HTTP 404" (pkg/cmd/api/api.go),
// and gh release download prints "HTTP 404: Not Found (URL)" (go-gh
// pkg/api/errors.go), "release not found" or "no assets match the file
// pattern" (pkg/cmd/release). A 429 is a rate limit, so it can pass later.
// GitHub often sends a rate limit as a 403 with "API rate limit exceeded" or
// "secondary rate limit" in the message.
var ghClientError = regexp.MustCompile(`HTTP 4(\d\d)\b|release not found|no assets match the file pattern`)

func ghPermanent(err error) bool {
	rateLimit := strings.Contains(strings.ToLower(err.Error()), "rate limit")
	return slices.ContainsFunc(ghClientError.FindAllStringSubmatch(err.Error(), -1), func(m []string) bool {
		return m[1] != "29" && (m[1] != "03" || !rateLimit)
	})
}

func githubReleaseDownload(ctx context.Context, args ...string) ([]byte, error) {
	return retryRead(ctx, ghPermanent, "gh", append([]string{"release", "download"}, args...)...)
}

// githubAPI passes --hostname, so that GH_HOST cannot change the host. gh
// api sends a POST when it gets a field or an input without a method. Thus
// only a call without a method, a field or an input runs again. A short flag
// can hold its value, as in -XPOST or -fname=x.
func githubAPI(ctx context.Context, args ...string) ([]byte, error) {
	args = append([]string{"api", "--hostname", "github.com"}, args...)
	if slices.ContainsFunc(args, func(a string) bool {
		flag, _, _ := strings.Cut(a, "=")
		return slices.Contains([]string{"--method", "--raw-field", "--field", "--input"}, flag) ||
			!strings.HasPrefix(a, "--") && (strings.HasPrefix(a, "-X") || strings.HasPrefix(a, "-f") || strings.HasPrefix(a, "-F"))
	}) {
		return github(ctx, args...)
	}
	return retryRead(ctx, ghPermanent, "gh", args...)
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
