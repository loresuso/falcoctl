package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/falcosecurity/falcoctl/internal/artifact/install"
	"github.com/falcosecurity/falcoctl/internal/index/add"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type runOptions struct {
	*options.CommonOptions
}

func NewRun(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := runOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "run falcoctl daemon",
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Run(ctx, args))
		},
	}

	return cmd
}

func (o *runOptions) Run(ctx context.Context, args []string) error {
	// Get config file
	var config Config

	file, err := os.Open(configFile)
	if err != nil {
		return fmt.Errorf("unable to open file %q: %w", configFile, err)
	}
	defer file.Close()

	buf, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("unable to read file %q, %w", configFile, err)
	}

	if err := yaml.Unmarshal(buf, &config); err != nil {
		return fmt.Errorf("unable to unmarshal config: %w", err)
	}

	// Log into necessary services
	// todo -> consider oauth type!!
	// todo -> make run login not interactive (in some cases) to call it directly
	for _, configuredAuth := range config.Auths {
		switch configuredAuth.AuthType {
		case "oauth":
			return fmt.Errorf("todo")
		case "basic":
			cred := &auth.Credential{
				Username: configuredAuth.User,
				Password: configuredAuth.Token,
			}

			client := authn.NewClient(authn.WithCredentials(cred))
			r, err := registry.NewRegistry(configuredAuth.Registry, registry.WithClient(client))
			if err != nil {
				return err
			}

			if err := r.CheckConnection(ctx); err != nil {
				o.Printer.Verbosef("%s", err.Error())
				return fmt.Errorf("unable to connect to registry %q: %w", configuredAuth.Registry, err)
			}

			// Store validated credentials
			err = authn.Login(configuredAuth.Registry, cred.Username, cred.Password)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("not recognized authentication type: %q", configuredAuth.AuthType)
		}

	}

	o.Printer.Info.Printfln("Correctly logged in to all configured registries")

	// Add all configured indexes
	for _, configuredIndex := range config.Indexes {
		indexAddOptions := add.IndexAddOptions{
			CommonOptions: o.CommonOptions,
		}

		err = indexAddOptions.RunIndexAdd(ctx, []string{configuredIndex.Name, configuredIndex.Url})
		if err != nil {
			return err
		}
	}

	o.Printer.Info.Printfln("Correctly added all configured indexes")

	// Install artifacts
	// todo: add option to discriminate between install and follow to this run command
	// for now just install..
	artifactInstallOptions := install.ArtifactInstallOptions{
		CommonOptions: o.CommonOptions,
		RegistryOptions: &options.RegistryOptions{
			PlainHTTP: config.PlainHTTP,
			Oauth:     config.Oauth,
		},
		PluginsDir:    config.PluginsDir,
		RulesfilesDir: config.RulesfilesDir,
	}

	var artifacts []string
	for _, artifact := range config.Artifacts {
		artifacts = append(artifacts, artifact.Name)
	}

	err = artifactInstallOptions.RunArtifactInstall(ctx, artifacts)
	if err != nil {
		return err
	}

	return nil
}
