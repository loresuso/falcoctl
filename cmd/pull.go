// Copyright 2022 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

type pullOptions struct {
	*commonoptions.CommonOptions
	artifactType oci.ArtifactType
	platform     string
}

func (o *pullOptions) Validate() error {
	//TODO(loresuso,alacuku): valid only for plugins artifacts, add check for supported platforms.
	if o.platform != "" && !strings.Contains(o.platform, "/") {
		return fmt.Errorf("wrong platform format: it needs to be in OS/ARCH")
	}
	return nil
}

// NewPullCmd returns the pull command.
func NewPullCmd(opt *commonoptions.CommonOptions) *cobra.Command {
	o := pullOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "pull hostname/repo:tag",
		DisableFlagsInUseLine: true,
		Short:                 "Pull a Falco OCI artifact from a registry",
		Long:                  "Pull Falco rules or plugins OCI artifacts from a registry",
		Args:                  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPull(args))
		},
	}
	cmd.Flags().VarP(&o.artifactType, "type", "t", `type of artifact to be pushed. Allowed values: "rule", "plugin"`)
	err := cmd.MarkFlagRequired("type")
	if err != nil {
		o.Printer.Error.Println("cannot mark type flag as required")
	}
	cmd.Flags().StringVar(&o.platform, "platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"os and architecture of the artifact in OS/ARCH format(only for plugins artifacts)")

	return cmd
}

// RunPull executes the business logic for the pull command.
func (o *pullOptions) RunPull(args []string) error {
	ctx := context.TODO()
	ref := args[0]
	index := strings.Index(ref, "/")
	if index <= 0 {
		return fmt.Errorf("cannot extract registry name")
	}

	registry := ref[0:index]

	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return err
	}
	cred, err := credentialStore.Credential(ctx, registry)
	if err != nil {
		return err
	}
	client := authn.NewClient(cred)

	puller := ocipuller.NewPuller(client)

	res, err := puller.Pull(ctx, o.artifactType, ref, "", o.platform)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	o.Printer.DefaultText.Printf("Artifact pulled. Digest: %s\n", res.Digest)
	return nil
}
