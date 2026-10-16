package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

var (
	// A release can have the stable flag and still carry a prerelease
	// version, so the tag must not have a suffix like "-rc1".
	tagPattern        = regexp.MustCompile(`^[^/]+/v[0-9]+\.[0-9]+\.[0-9]+$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	policyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	policyIDPattern   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	errExcluded       = errors.New("the policy is excluded from publishing (see excluded_policies in the config file)")
)

// discover returns the upstream releases that have no published release in
// repo. A draft is the remainder of a failed run, so it does not count. A
// pinned version is also returned when it has a published release.
func discover(ctx context.Context, cfg *config, repo, name, version string) ([]map[string]string, error) {
	if version != "" && name == "" {
		return nil, errors.New("discover: a pinned policy version needs a policy name")
	} else if slices.Contains(cfg.ExcludedPolicies, name) {
		return nil, fmt.Errorf("discover: %s: %w", name, errExcluded)
	}
	upstream, err1 := releasesOf(ctx, cfg.Upstream.Repository)
	dest, err2 := releasesOf(ctx, repo)
	tags, err3 := tagsOf(ctx, repo)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	var candidates []map[string]string
	latest := map[string]map[string]string{}
	for _, r := range upstream {
		if e := candidate(r); e != nil {
			candidates = append(candidates, e)
			if cur := latest[e["policy_name"]]; cur == nil || versionLess(cur["version"], e["version"]) {
				latest[e["policy_name"]] = e
			}
		}
	}
	released := map[string]bool{}
	for _, r := range dest {
		released[str(r, "tag_name")] = released[str(r, "tag_name")] || get(r, "draft") != true
	}
	selected := slices.Collect(maps.Values(latest))
	if version != "" {
		// A pinned version can be older than the latest one.
		selected = slices.DeleteFunc(candidates, func(e map[string]string) bool { return e["policy_name"] != name || e["version"] != version })
	} else if name != "" {
		selected = slices.DeleteFunc(selected, func(e map[string]string) bool { return e["policy_name"] != name })
	}
	if name != "" && len(selected) == 0 {
		return nil, fmt.Errorf("discover: no upstream release matches policy %q version %q", name, cmp.Or(version, "<latest>"))
	}
	slices.SortStableFunc(selected, func(a, b map[string]string) int { return cmp.Compare(a["policy_name"], b["policy_name"]) })
	out := []map[string]string{}
	for _, e := range selected {
		// A pinned version goes on to the repackage job, which verifies the
		// published release. Thus a person can check a release whose
		// publication response got lost.
		if excluded := slices.Contains(cfg.ExcludedPolicies, e["policy_name"]); excluded || released[e["tag"]] && version == "" {
			logf("skip %s: %s", e["tag"], map[bool]string{true: "the policy is excluded from publishing", false: repo + " already has the release"}[excluded])
			continue
		} else if released[e["tag"]] {
			logf("%s already has the release %s. The repackage job verifies the published release", repo, e["tag"])
		} else if tags[e["tag"]] {
			// The repackage job stops at such a tag. After someone deletes an
			// immutable release, nobody can use its tag again. Without the
			// skip, each full run fails until upstream releases a newer version.
			err := fmt.Errorf("the tag exists in %s without a published release. A person must check the tag", repo)
			if name != "" {
				return nil, fmt.Errorf("discover: %s: %w", e["tag"], err)
			}
			logf("::warning::%s", escapeData(fmt.Sprintf("skip %s: %v. The other policies are not affected", e["tag"], err)))
			continue
		}
		id, skip, err := policyID(ctx, cfg, e)
		// Without a filter, a problem of one release does not stop the others.
		if skip && name == "" {
			logf("::warning::%s", escapeData(fmt.Sprintf("skip %s: %v. The other policies are not affected", e["tag"], err)))
			continue
		} else if err != nil {
			return nil, fmt.Errorf("discover: %s: %w", e["tag"], err)
		}
		e["policy_id"] = id
		logf("queue %s (policy id: %s)", e["tag"], id)
		out = append(out, e)
	}
	return out, nil
}

// With --slurp, gh writes the pages as one JSON list of lists.
func releasesOf(ctx context.Context, repo string) ([]any, error) {
	pages, err := decode(githubAPI(ctx, "--paginate", "--slurp", "repos/"+repo+"/releases"))
	var all []any
	for _, p := range list(pages) {
		all = append(all, list(p)...)
	}
	return all, err
}

// matching-refs gives an empty list when the repository has no tag. Its
// documentation lists no 404, only a 409 for a repository without commits.
func tagsOf(ctx context.Context, repo string) (map[string]bool, error) {
	pages, err := decode(githubAPI(ctx, "--paginate", "--slurp", "repos/"+repo+"/git/matching-refs/tags/"))
	tags := map[string]bool{}
	for _, p := range list(pages) {
		for _, r := range list(p) {
			if tag, ok := strings.CutPrefix(str(r, "ref"), "refs/tags/"); ok {
				tags[tag] = true
			}
		}
	}
	return tags, err
}

func candidate(release any) map[string]string {
	tag := str(release, "tag_name")
	name, version, _ := strings.Cut(tag, "/v")
	if get(release, "draft") == true || get(release, "prerelease") == true || !tagPattern.MatchString(tag) || !policyNamePattern.MatchString(name) {
		return nil
	}
	return map[string]string{"policy_name": name, "version": version, "tag": tag, "upstream_release_url": str(release, "html_url")}
}

func versionLess(a, b string) bool {
	var x, y [3]int
	_, _ = fmt.Sscanf(a, "%d.%d.%d", &x[0], &x[1], &x[2])
	_, _ = fmt.Sscanf(b, "%d.%d.%d", &y[0], &y[1], &y[2])
	return slices.Compare(x[:], y[:]) < 0
}

// checkPolicy checks the name and the version before they go into a path.
func checkPolicy(cfg *config, name, version string) error {
	switch {
	case !policyNamePattern.MatchString(name):
		return fmt.Errorf("the policy name %q has characters that are not allowed (%s)", name, policyNamePattern)
	case !versionPattern.MatchString(version):
		return fmt.Errorf("the version %q is not X.Y.Z", version)
	case slices.Contains(cfg.ExcludedPolicies, name):
		return fmt.Errorf("%s: %w", name, errExcluded)
	}
	return nil
}

// policyID reads the ociUrl annotation of the upstream metadata.yml at the
// tag. skip is true for a problem of this release only, for example a
// missing file. Any other failure of gh can hide every release.
func policyID(ctx context.Context, cfg *config, e map[string]string) (id string, skip bool, err error) {
	file := "policies/" + e["policy_name"] + "/metadata.yml"
	// With the raw media type, gh does not change the control characters.
	data, err := githubAPI(ctx, "-H", "Accept: application/vnd.github.raw", "--allow-escape-sequences",
		"repos/"+cfg.Upstream.Repository+"/contents/"+file+"?ref="+url.QueryEscape(e["tag"]))
	if err != nil {
		return "", strings.Contains(err.Error(), "HTTP 404"), fmt.Errorf("read %s at %s: %w", file, e["tag"], err)
	}
	var md any
	if err := yaml.Unmarshal(data, &md); err != nil {
		return "", true, fmt.Errorf("parse %s: %w", file, err)
	}
	ociURL := str(md, "annotations", keyOCIURL)
	if id = ociURL[strings.LastIndex(ociURL, "/")+1:]; !policyIDPattern.MatchString(id) {
		return "", true, fmt.Errorf("the %s annotation %q does not end with a valid policy id (%s)", keyOCIURL, ociURL, policyIDPattern)
	} else if v := str(md, "annotations", keyVersion); v != e["version"] {
		return "", true, fmt.Errorf("tag version %q does not match the metadata version %q", e["version"], v)
	}
	return id, false, nil
}
