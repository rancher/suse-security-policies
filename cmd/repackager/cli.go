package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func newRootCommand() *cobra.Command {
	var configPath, policyName, policyVersion string
	var data repackageData
	root := &cobra.Command{Use: "repackager", Short: "Repackage upstream Kubewarden policies as SUSE policies", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&configPath, "config", "config.yaml", "path of the config file")

	checkConfig := &cobra.Command{
		Use: "check-config", Short: "Check that the config file has every value the pipeline needs", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := loadConfig(configPath)
			if err == nil {
				_, err = fmt.Fprintf(cmdOut, "%s is valid\n", configPath)
			}
			return err
		},
	}

	discoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Find the upstream releases that still need a repackaging",
		Long: `Find the upstream releases that still need a repackaging. Print them as a
compact JSON list on stdout. In GitHub Actions, also set the step outputs
"matrix" and "count" and write the job summary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := setup(cmd, configPath, "repository")
			if err != nil {
				return err
			}
			releases, err := discover(cmd.Context(), cfg, data.repo, policyName, policyVersion)
			if err != nil {
				return err
			}
			matrix, _ := json.Marshal(releases)
			fmt.Fprintf(cmdOut, "%s\n", matrix)
			if err := appendEnvFile("GITHUB_OUTPUT", io.Discard, fmt.Sprintf("matrix=%s\ncount=%d\n", matrix, len(releases))); err != nil {
				return err
			}
			// Outside GitHub Actions, stdout holds only the JSON list.
			return appendEnvFile("GITHUB_STEP_SUMMARY", logOut, discoverySummary(releases, data.dryRun))
		},
	}
	df := discoverCmd.Flags()
	df.StringVar(&data.repo, "repository", "", "owner/repo of this repository (required)")
	df.StringVar(&policyName, "policy-name", "", "find only the release of this policy")
	df.StringVar(&policyVersion, "policy-version", "", "find only this version, without the 'v' prefix. Needs --policy-name")
	df.BoolVar(&data.dryRun, "dry-run", false, "mark the job summary as a dry run")

	repackageCmd := &cobra.Command{
		Use:   "repackage",
		Short: "Repackage one upstream policy release",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := setup(cmd, configPath, "repository", "sha", "policy-name", "policy-version")
			if err != nil {
				return err
			}
			data.cfg, data.name, data.version = cfg, policyName, policyVersion
			return repackage(cmd.Context(), &data)
		},
	}
	rf := repackageCmd.Flags()
	rf.StringVar(&data.repo, "repository", "", "owner/repo of this repository (required)")
	rf.StringVar(&data.sha, "sha", "", "commit of this repository that runs the pipeline (required)")
	rf.StringVar(&policyName, "policy-name", "", "name of the upstream policy, for example pod-privileged-policy (required)")
	rf.StringVar(&policyVersion, "policy-version", "", "version of the upstream policy, without the 'v' prefix (required)")
	rf.BoolVar(&data.dryRun, "dry-run", false, "push, sign and publish nothing, but run every check that only reads")
	rf.StringVar(&data.workDir, "work-dir", "", "keep the files of the run in this directory, instead of a temporary directory")

	root.AddCommand(checkConfig, discoverCmd, repackageCmd)
	return root
}

// setup rejects an empty required flag, because make passes an unset
// variable as an empty string.
func setup(cmd *cobra.Command, configPath string, required ...string) (*config, error) {
	var missing []string
	for _, name := range required {
		if strings.TrimSpace(cmd.Flags().Lookup(name).Value.String()) == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("these flags are required and must not be empty: %s", strings.Join(missing, ", "))
	}
	return loadConfig(configPath)
}
