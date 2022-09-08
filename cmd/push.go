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
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

type pushOptions struct {
	*commonoptions.CommonOptions
	artifactType oci.ArtifactType
	platform     string
	dependencies []string
}

func (o *pushOptions) Validate() error {
	r := regexp.MustCompile(`^[a-z]+:\d+.\d+.\d+`)

	for _, dep := range o.dependencies {
		if ok := r.MatchString(dep); !ok {
			return fmt.Errorf("wrong dependency format: %s", dep)
		}
	}

	//TODO(loresuso,alacuku): valid only for plugins artifacts, add check for supported platforms.
	if o.platform != "" && !strings.Contains(o.platform, "/") {
		return fmt.Errorf("wrong platform format: it needs to be in OS/ARCH")
	}

	return nil
}

// NewPushCmd returns the push command.
func NewPushCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	o := pushOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "push filename hostname/repo:tag",
		DisableFlagsInUseLine: true,
		Short:                 "Push a Falco OCI artifact to a registry",
		Long:                  "Push Falco rules or plugins OCI artifacts to a registry",
		Args:                  cobra.ExactArgs(2),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPush(ctx, args))
		},
	}

	cmd.Flags().VarP(&o.artifactType, "type", "t", `type of artifact to be pushed. Allowed values: "rule", "plugin"`)
	cmd.Flags().StringVar(&o.platform, "platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"os and architecture of the artifact in OS/ARCH format(only for plugins artifacts)")
	err := cmd.MarkFlagRequired("type")
	if err != nil {
		o.Printer.Error.Println("cannot mark type flag as required")
	}
	cmd.Flags().StringArrayVarP(&o.dependencies, "dependency", "d", []string{},
		"define a rule to plugin dependency. Example: '--dependency cloudtrail:1.2.3")

	return cmd
}

// RunPush executes the business logic for the push command.
func (o *pushOptions) RunPush(ctx context.Context, args []string) error {
	path := args[0]
	ref := args[1]
	index := strings.Index(ref, "/")
	if index <= 0 {
		o.Printer.Error.Printf("unable to extract registry name from %s", ref)
		return fmt.Errorf("cannot extract registry name from %s", ref)
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

	pusher, err := ocipusher.NewPusher(ctx, client)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	res, err := pusher.Push(ctx, o.artifactType, path, ref, o.platform, o.dependencies...)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	o.Printer.DefaultText.Printf("Artifact pushed. Digest: %s\n", res.Digest)

	return nil
}
