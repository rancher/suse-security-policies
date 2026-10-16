package main

import (
	"fmt"
	"regexp"
	"strings"
)

// The character before "#" or "@" must not be part of a word, a path, a domain
// or code, so "owner/repo#12", "a.b#1" and e-mail addresses stay unchanged.
var (
	issueRefPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_/.-])#([0-9]+)`)
	mentionPattern  = regexp.MustCompile("(^|[^A-Za-z0-9_`/])@([A-Za-z0-9][A-Za-z0-9-]*)")
)

// rewriteChangelog links a bare "#123" to the upstream issue, and changes
// "@user" to "`@user`", so that nobody gets a notification.
func rewriteChangelog(body, upstreamRepo string) string {
	// "$" starts a group reference in a Go replacement.
	issueRepl := "${1}" + strings.ReplaceAll(upstreamRepo, "$", "$$") + "#${2}"
	// Line by line, "^" is the start of a line and no class matches "\n".
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		line = issueRefPattern.ReplaceAllString(line, issueRepl)
		lines[i] = mentionPattern.ReplaceAllString(line, "${1}`@${2}`")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func renderReleaseNotes(d *repackageData, destRef, body string) string {
	return fmt.Sprintf("This is a SUSE repackage of the upstream Kubewarden policy\n`%s` %s.\n\n", d.name, d.version) +
		"The WebAssembly module comes from the upstream release pipeline. The workflow\n" +
		"checked its signature and pulled it by digest. Then kwctl annotate replaced\n" +
		"the provenance metadata and wrote the module out again. The workflow signed\n" +
		"the result with the identity of this repository.\n\n| | |\n|---|---|\n" +
		fmt.Sprintf("| Upstream release | [%s](%s) |\n", d.tag, d.url) +
		fmt.Sprintf("| Verified source | `%s/%s@%s` |\n", d.cfg.Upstream.Registry, d.id, d.upstreamDigest) +
		fmt.Sprintf("| Published artifact | `%s` |\n", destRef) +
		fmt.Sprintf("| Upstream source code | `%s`, commit [`%s`](https://github.com/%s/tree/%s), sha256 `%s` |\n",
			sourceArchiveName, d.sourceCommit, d.cfg.Upstream.Repository, d.sourceCommit, d.sourceSHA256) +
		"\n## Changelog\n\n" + rewriteChangelog(body, d.cfg.Upstream.Repository) + "\n"
}

func releaseSummary(d *repackageData, checkFailure, cleanupFailure string) string {
	s := "### Repackaged " + d.tag + "\n\n"
	if checkFailure != "" {
		s += "> A check after the publication failed: " + strings.Join(strings.Fields(checkFailure), " ") + ". The release is published and immutable. Fix it by hand.\n\n"
	}
	if cleanupFailure != "" {
		s += "> The release is published, but the run cannot delete one or more old drafts for the tag: " + strings.Join(strings.Fields(cleanupFailure), " ") + ". Delete them by hand.\n\n"
	}
	upstreamSum, _ := fileSHA256(d.path(upstreamSBOMName))
	suseSum, _ := fileSHA256(d.path(suseSBOMName))
	return s + fmt.Sprintf("| | |\n|---|---|\n| Verified upstream digest | `%s` |\n| Published artifact | `%s` |\n| Release | %s |\n"+
		"| Upstream source commit | `%s` |\n| Upstream source archive sha256 | `%s` |\n| Upstream SBOM sha256 | `%s` |\n"+
		"| SUSE SBOM sha256 | `%s` |\n| SUSE SBOM namespace | `%s` |\n",
		d.upstreamDigest, d.immutableRef, d.tag, d.sourceCommit, d.sourceSHA256, upstreamSum, suseSum, d.suseNamespace)
}

func publishedSummary(d *repackageData, failure string) string {
	s := "### Verified the published release " + d.tag + "\n\n"
	if failure != "" {
		s = "### Published release " + d.tag + "\n\n> A check of the published release failed: " + strings.Join(strings.Fields(failure), " ") + ". The release is published and immutable. Check it by hand.\n\n"
	} else {
		s += "The release is already published, so the run did not repackage the policy. The run verified the published release.\n\n"
	}
	return s + fmt.Sprintf("| | |\n|---|---|\n| Published artifact | `%s` |\n| Release | %s |\n| Release commit | `%s` |\n",
		d.immutableRef, d.tag, str(d.published, "target_commitish"))
}

func discoverySummary(releases []map[string]string, dryRun bool) string {
	s := "### Policies queued for repackaging\n\n"
	if dryRun {
		s += "Dry run: the workflow publishes nothing.\n\n"
	}
	if len(releases) == 0 {
		return s + "Nothing to do. Every upstream release already has a matching release here.\n"
	}
	s += "| Policy | Version | Upstream release |\n|---|---|---|\n"
	for _, r := range releases {
		s += fmt.Sprintf("| %s | %s | [%s](%s) |\n", r["policy_name"], r["version"], r["tag"], r["upstream_release_url"])
	}
	return s
}
