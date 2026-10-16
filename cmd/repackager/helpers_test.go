package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRetryRead(t *testing.T) {
	never := func(error) bool { return false }
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name      string
		ctx       context.Context
		sleepErr  error
		wantCalls int
		wantWaits []time.Duration
		wantLog   []string
	}{
		{name: "warning before each new try", ctx: context.Background(), wantCalls: 3, wantWaits: []time.Duration{2 * time.Second, 8 * time.Second},
			wantLog: []string{"::warning::gh api repos/a/b failed: gh: Server Error (HTTP 502)%0Aline 2. The run tries again in 2s.",
				"::warning::gh api repos/a/b failed: gh: Server Error (HTTP 502)%0Aline 2. The run tries again in 8s."}},
		{name: "cancelled context", ctx: cancelled, wantCalls: 1, wantWaits: []time.Duration{}},
		{name: "context ends during the wait", ctx: context.Background(), sleepErr: context.Canceled, wantCalls: 1, wantWaits: []time.Duration{2 * time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t, "", rule{prefix: "gh api repos/a/b", err: "gh: Server Error (HTTP 502)\nline 2"})
			var log bytes.Buffer
			logOut = &log
			f.waits = []time.Duration{}
			sleep = func(_ context.Context, d time.Duration) error {
				f.waits = append(f.waits, d)
				return tt.sleepErr
			}
			_, err := retryRead(tt.ctx, never, "gh", "api", "repos/a/b")
			if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
				t.Errorf("retryRead returned the error %v instead of the error of the last try", err)
			}
			if len(f.calls) != tt.wantCalls || !slices.Equal(f.waits, tt.wantWaits) {
				t.Errorf("retryRead ran %d times and waited %v, expected %d times and %v", len(f.calls), f.waits, tt.wantCalls, tt.wantWaits)
			}
			for _, w := range tt.wantLog {
				if !strings.Contains(log.String(), w+"\n") {
					t.Errorf("the log does not contain %q:\n%s", w, log.String())
				}
			}
		})
	}
}

func TestSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Errorf("sleep returned %v after %s, expected context.Canceled at once", err, time.Since(start))
	}
	if err := sleep(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleep returned %v", err)
	}
}

func TestGHPermanent(t *testing.T) {
	for msg, want := range map[string]bool{
		"gh: gh: Not Found (HTTP 404)":                                               true,
		"gh: exit status 1: gh: HTTP 404":                                            true,
		"gh: exit status 1: HTTP 404: Not Found (https://x/y)":                       true,
		"gh: exit status 1: gh: Bad credentials (HTTP 401)":                          true,
		"gh: exit status 1: release not found":                                       true,
		"gh: exit status 1: no assets match the file pattern":                        true,
		"gh: exit status 1: gh: API rate limit exceeded (HTTP 429)":                  false,
		"gh: exit status 1: gh: Server Error (HTTP 502)":                             false,
		"gh: exit status 1: dial tcp: connection reset by peer":                      false,
		"gh: exit status 1: HTTP 4000 is not a status":                               false,
		"gh: exit status 1: gh: Too Many (HTTP 429)\ngh: (HTTP 404)":                 true,
		"gh: exit status 1: gh: API rate limit exceeded for user ID 1. (HTTP 403)":   false,
		"gh: exit status 1: gh: You have exceeded a secondary rate limit (HTTP 403)": false,
		"gh: exit status 1: gh: Resource not accessible by integration (HTTP 403)":   true,
	} {
		if got := ghPermanent(errors.New(msg)); got != want {
			t.Errorf("ghPermanent(%q) is %v instead of %v", msg, got, want)
		}
	}
}

func TestGitHubAPIWrites(t *testing.T) {
	for _, args := range [][]string{{"-X", "GET", "p"}, {"--method=GET", "p"}, {"p", "-f", "a=b"}, {"p", "-F", "a=1"}, {"p", "--raw-field", "a=b"}, {"p", "--field=a=1"}, {"p", "--input", "f"},
		{"-XPOST", "p"}, {"p", "-fa=b"}, {"p", "-Fa=b"}, {"--method=POST", "p"}} {
		f := newFake(t, "", rule{prefix: "gh api", err: "gh: Server Error (HTTP 502)"})
		if _, err := githubAPI(context.Background(), args...); err == nil || len(f.calls) != 1 || len(f.waits) != 0 {
			t.Errorf("githubAPI %q ran %d times and waited %v, expected one try", args, len(f.calls), f.waits)
		}
	}
}
