package cmd

import (
	"fmt"
	"os"

	"github.com/falcosecurity/falcoctl/pkg/registry"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewSearchRegistryCmd(options CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registry",
		DisableFlagsInUseLine: true,
		Short:                 "Search a plugin inside the official Falco registry",
		Long:                  `Search a plugin inside the official Falco registry`,
		Run: func(cmd *cobra.Command, args []string) {
			var output string
			all, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Error(err)
			}

			if !all && len(args) == 0 {
				logger.Error("Please provide one or more arguments or --all/-a flag")
				return
			}
			// put url and path in config file
			err = registry.DownloadRegistry("https://raw.githubusercontent.com/falcosecurity/plugins/master/registry.yaml", "/tmp/registry.yaml")
			if err != nil {
				logger.Error("Cannot download plugin registry")
				return
			}
			file, err := os.Open("/tmp/registry.yaml")
			if err != nil {
				return
			}
			defer file.Close()
			defer os.Remove("/tmp/registry.yaml")

			registry, err := registry.LoadRegistry(file)
			if err != nil {
				logger.Error(err)
				return
			}

			if all {
				output, err = registry.Plugins.ToString()
			} else {
				plugins := registry.SearchByKeywords(args)
				output, err = plugins.ToString()
			}

			if err != nil {
				logger.Error(err)
			}

			fmt.Println(output)
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP("all", "a", false, "print all entries in the registry")

	return cmd
}
