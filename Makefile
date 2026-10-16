BIN_DIR := bin
BINARY := $(BIN_DIR)/repackager

# Tools. Renovate updates each version and its checksums together.
# Keep each "renovate:" comment on the line just above its value. See renovate.json.

# renovate: datasource=github-release-attachments depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION := v2.14.0
# renovate: datasource=github-release-attachments depName=golangci/golangci-lint digestVersion=v2.14.0
GOLANGCI_LINT_SHA256_linux_amd64 := ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab

# renovate: datasource=github-release-attachments depName=rhysd/actionlint
ACTIONLINT_VERSION := v1.7.12
# renovate: datasource=github-release-attachments depName=rhysd/actionlint digestVersion=v1.7.12
ACTIONLINT_SHA256_linux_amd64 := 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8

# renovate: datasource=github-release-attachments depName=koalaman/shellcheck
SHELLCHECK_VERSION := v0.11.0
# renovate: datasource=github-release-attachments depName=koalaman/shellcheck digestVersion=v0.11.0
SHELLCHECK_SHA256_linux_amd64 := b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6

# kwctl 1.39 is the first version whose "annotate" changes single
# annotations. Use v1.39.0 when it is released.
# renovate: datasource=github-release-attachments depName=kubewarden/adm-controller
KWCTL_VERSION := v1.39.0-rc.1
# renovate: datasource=github-release-attachments depName=kubewarden/adm-controller digestVersion=v1.39.0-rc.1
KWCTL_SHA256_linux_amd64 := 5f91372672e3098b8041f9db9e3f44382955123a24777b1671639704b4af5161

# renovate: datasource=github-release-attachments depName=CycloneDX/sbom-utility
SBOM_UTILITY_VERSION := v0.19.2
# renovate: datasource=github-release-attachments depName=CycloneDX/sbom-utility digestVersion=v0.19.2
SBOM_UTILITY_SHA256_linux_amd64 := e0cd37e6e67b1d0e44dbb7b38e055a4e2ee66db590bb8e7f89e2d9b650f4490b

# renovate: datasource=github-release-attachments depName=sigstore/cosign
COSIGN_VERSION := v3.1.3
# renovate: datasource=github-release-attachments depName=sigstore/cosign digestVersion=v3.1.3
COSIGN_SHA256_linux_amd64 := 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71

# renovate: datasource=github-release-attachments depName=cli/cli
GH_VERSION := v2.102.0
# renovate: datasource=github-release-attachments depName=cli/cli digestVersion=v2.102.0
GH_SHA256_linux_amd64 := bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386

# govulncheck has no release binaries, so "go install" builds it. Go
# checks the module against go.sum of the module and the Go checksum
# database, so there is no sha256 here.
# renovate: datasource=go depName=golang.org/x/vuln
GOVULNCHECK_VERSION := v1.9.0

# The version is part of each file name. A new version gives a new file
# name, so make installs the tool again.
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)
ACTIONLINT := $(BIN_DIR)/actionlint-$(ACTIONLINT_VERSION)
SHELLCHECK := $(BIN_DIR)/shellcheck-$(SHELLCHECK_VERSION)
KWCTL := $(BIN_DIR)/kwctl-$(KWCTL_VERSION)
SBOM_UTILITY := $(BIN_DIR)/sbom-utility-$(SBOM_UTILITY_VERSION)
COSIGN := $(BIN_DIR)/cosign-$(COSIGN_VERSION)
GH := $(BIN_DIR)/gh-$(GH_VERSION)
GOVULNCHECK := $(BIN_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
RUNTIME_TOOLS := $(KWCTL) $(SBOM_UTILITY) $(COSIGN) $(GH)
# The repackager runs each runtime tool by its plain name from PATH, so each
# tool also gets a symlink without the version.
RUNTIME_TOOL_LINKS := $(BIN_DIR)/kwctl $(BIN_DIR)/sbom-utility $(BIN_DIR)/cosign $(BIN_DIR)/gh
TOOLS := $(GOLANGCI_LINT) $(ACTIONLINT) $(SHELLCHECK) $(GOVULNCHECK) $(RUNTIME_TOOLS) $(RUNTIME_TOOL_LINKS)

UNAME := $(shell uname -s)/$(shell uname -m)
OS :=
ifeq ($(UNAME),Linux/x86_64)
OS := linux
ARCH := amd64
UNAME_ARCH := x86_64
endif
PLATFORM := $(OS)_$(ARCH)

# $(call install-tool,url,sha256,extract command): downloads url, checks its
# sha256 and installs the file that the extract command writes to $@.tmp.
define install-tool
	@test -n "$(OS)" || { echo "Cannot install $(@F) on $(UNAME). Only Linux/x86_64 is supported." >&2; exit 1; }
	@mkdir -p $(@D)
	curl -fsSL --retry 3 -o $@.download $(1)
	echo "$(2)  $@.download" | sha256sum -c -
	$(3)
	chmod 755 $@.tmp
	rm -f $@.download
	mv $@.tmp $@
endef

.PHONY: build
build:
	go build -o $(BINARY) ./cmd/repackager

.PHONY: test
test:
	go test -race ./...

.PHONY: fmt-check
fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not formatted with gofmt:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

# Without shellcheck, actionlint skips the checks of the "run" scripts and
# does not fail.
.PHONY: actionlint
actionlint: $(ACTIONLINT) $(SHELLCHECK)
	$(ACTIONLINT) -color -shellcheck $(SHELLCHECK)

.PHONY: mod-check
mod-check:
	go mod tidy -diff

.PHONY: vulncheck
vulncheck: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

.PHONY: check-config
check-config: build
	$(BINARY) check-config

# The installer actions in the sync workflow read their own copy of these two
# pins. Renovate updates both copies, but a manual edit or a partial merge can
# change only one.
SYNC_WORKFLOW := .github/workflows/sync-upstream-releases.yaml

.PHONY: check-pins
check-pins:
	@status=0; \
	for pin in KWCTL_VERSION=$(KWCTL_VERSION) COSIGN_VERSION=$(COSIGN_VERSION); do \
		name="$${pin%%=*}"; \
		want="$${pin#*=}"; \
		got="$$(awk -v name="$$name" '$$1 == name ":" { gsub(/["\047]/, "", $$2); print $$2 }' $(SYNC_WORKFLOW) | sort -u)"; \
		if [ -z "$$got" ]; then \
			echo "$(SYNC_WORKFLOW) has no value for $$name. The Makefile pins $$want." >&2; \
			status=1; \
		elif [ "$$(printf '%s\n' "$$got" | wc -l)" -gt 1 ]; then \
			echo "$(SYNC_WORKFLOW) pins $$name to different values: $$(echo $$got). The Makefile pins $$want. Change all pins to the same version." >&2; \
			status=1; \
		elif [ "$$got" != "$$want" ]; then \
			echo "$(SYNC_WORKFLOW) pins $$name to $$got, but the Makefile pins $$want. Change both pins to the same version." >&2; \
			status=1; \
		fi; \
	done; \
	exit $$status

.PHONY: tools
tools: $(TOOLS)

.PHONY: runtime-tools
runtime-tools: $(RUNTIME_TOOLS) $(RUNTIME_TOOL_LINKS)

# The CI installs kwctl and cosign with their installer actions. No installer
# action exists for sbom-utility.
.PHONY: sbom-utility
sbom-utility: $(SBOM_UTILITY) $(BIN_DIR)/sbom-utility

# The runner image has a gh, but its version changes without review, and the
# repackager parses the output and the errors of gh.
.PHONY: gh
gh: $(GH) $(BIN_DIR)/gh

# The CI runs this check on the gh that it finds on the PATH. A gh that is
# missing or that prints no version gives an empty value, which fails.
.PHONY: check-gh-version
check-gh-version:
	@out="$$(gh --version)"; \
	printf '%s\n' "$$out"; \
	version="$$(printf '%s\n' "$$out" | awk 'NR == 1 { print $$3 }')"; \
	if [ "$$version" != "$(GH_VERSION:v%=%)" ]; then \
		echo "::error::gh is '$$version', but the Makefile pins $(GH_VERSION)"; \
		exit 1; \
	fi

# The repackager reads only GITHUB_OUTPUT and GITHUB_STEP_SUMMARY from the
# environment. gh reads GH_TOKEN (or GITHUB_TOKEN) itself, and cosign reads
# ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN itself.
# The repackager runs kwctl, sbom-utility, cosign and gh from PATH. The
# recipes put $(BIN_DIR) first in PATH, so the tools of "make runtime-tools"
# come before other copies. If bin/ has no copy of a tool, the repackager runs
# the copy that it finds next on the PATH. The CI works this way for kwctl and
# cosign.
# The other values come from these environment variables, and the recipes
# pass them as flags: REPOSITORY, SHA, POLICY_NAME, POLICY_VERSION, DRY_RUN
# and WORK_DIR. The recipes expand them in the shell, inside quotes, so make
# does not change a value and the shell does not split it. An empty WORK_DIR
# makes the repackager use a temporary directory. For a dry run, set
# DRY_RUN=true, for example "DRY_RUN=true make repackage".
.PHONY: discover
discover: build
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" $(BINARY) discover --repository "$$REPOSITORY" --policy-name "$$POLICY_NAME" --policy-version "$$POLICY_VERSION" --dry-run="$${DRY_RUN:-false}"

.PHONY: repackage
repackage: build
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" $(BINARY) repackage --repository "$$REPOSITORY" --sha "$$SHA" --policy-name "$$POLICY_NAME" --policy-version "$$POLICY_VERSION" --work-dir "$$WORK_DIR" --dry-run="$${DRY_RUN:-false}"

$(GOLANGCI_LINT):
	$(call install-tool,https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION:v%=%)-$(OS)-$(ARCH).tar.gz,$(GOLANGCI_LINT_SHA256_$(PLATFORM)),tar -xzOf $@.download golangci-lint-$(GOLANGCI_LINT_VERSION:v%=%)-$(OS)-$(ARCH)/golangci-lint > $@.tmp)

$(ACTIONLINT):
	$(call install-tool,https://github.com/rhysd/actionlint/releases/download/$(ACTIONLINT_VERSION)/actionlint_$(ACTIONLINT_VERSION:v%=%)_$(OS)_$(ARCH).tar.gz,$(ACTIONLINT_SHA256_$(PLATFORM)),tar -xzOf $@.download actionlint > $@.tmp)

$(SHELLCHECK):
	$(call install-tool,https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$(OS).$(UNAME_ARCH).tar.gz,$(SHELLCHECK_SHA256_$(PLATFORM)),tar -xzOf $@.download shellcheck-$(SHELLCHECK_VERSION)/shellcheck > $@.tmp)

$(KWCTL):
	$(call install-tool,https://github.com/kubewarden/adm-controller/releases/download/$(KWCTL_VERSION)/kwctl-$(OS)-$(UNAME_ARCH).zip,$(KWCTL_SHA256_$(PLATFORM)),unzip -p $@.download kwctl-$(OS)-$(UNAME_ARCH) > $@.tmp)

$(SBOM_UTILITY):
	$(call install-tool,https://github.com/CycloneDX/sbom-utility/releases/download/$(SBOM_UTILITY_VERSION)/sbom-utility-$(SBOM_UTILITY_VERSION)-$(OS)-$(ARCH).tar.gz,$(SBOM_UTILITY_SHA256_$(PLATFORM)),tar -xzOf $@.download sbom-utility > $@.tmp)

$(COSIGN):
	$(call install-tool,https://github.com/sigstore/cosign/releases/download/$(COSIGN_VERSION)/cosign-$(OS)-$(ARCH),$(COSIGN_SHA256_$(PLATFORM)),cp $@.download $@.tmp)

$(GH):
	$(call install-tool,https://github.com/cli/cli/releases/download/$(GH_VERSION)/gh_$(GH_VERSION:v%=%)_$(PLATFORM).tar.gz,$(GH_SHA256_$(PLATFORM)),tar -xzOf $@.download gh_$(GH_VERSION:v%=%)_$(PLATFORM)/bin/gh > $@.tmp)

$(BIN_DIR)/kwctl: $(KWCTL)
$(BIN_DIR)/sbom-utility: $(SBOM_UTILITY)
$(BIN_DIR)/cosign: $(COSIGN)
$(BIN_DIR)/gh: $(GH)

# make reads the time of the file that a symlink points to. If a pin goes back
# to an older version that is still in $(BIN_DIR), that file is older than the
# symlink target. FORCE makes the recipe run every time.
$(RUNTIME_TOOL_LINKS): FORCE
	ln -sfn $(notdir $(filter-out FORCE,$^)) $@

.PHONY: FORCE
FORCE:

# go install always names the binary govulncheck. The recipe installs it into
# a temporary directory and renames it, so $(BIN_DIR) gets only the file with
# the version.
$(GOVULNCHECK):
	rm -rf $@.gobin
	GOBIN=$(CURDIR)/$@.gobin go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	mv $@.gobin/govulncheck $@
	rm -rf $@.gobin
