// Command repackager repackages upstream Kubewarden policies as SUSE policies.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var logOut, cmdOut io.Writer = os.Stderr, os.Stdout

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil {
		logf("::error::%s", escapeData(err.Error()))
		os.Exit(1)
	}
}

func logf(format string, args ...any) { fmt.Fprintf(logOut, format+"\n", args...) }

// escapeData keeps the stderr of a tool from starting a workflow command.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func appendEnvFile(env string, fallback io.Writer, text string) error {
	path := os.Getenv(env)
	if path == "" {
		_, err := io.WriteString(fallback, text)
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		_, err = io.WriteString(f, text)
		err = errors.Join(err, f.Close())
	}
	return err
}
