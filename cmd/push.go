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
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type pushOptions struct {
	*commonoptions.ConfigOptions
	artifactType oci.ArtifactType
	dependencies []string
}

func (o *pushOptions) Validate() error {
	r := regexp.MustCompile(`^[a-z]+:\d+.\d+.\d+`)

	for _, dep := range o.dependencies {
		if ok := r.MatchString(dep); !ok {
			return fmt.Errorf("wrong dependency format: %s", dep)
		}
	}

	return nil
}

// NewPushCmd returns the push command.
func NewPushCmd(opt *commonoptions.ConfigOptions) *cobra.Command {
	o := pushOptions{
		ConfigOptions: opt,
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
			output.ExitOnErr(o.RunPush(args))
		},
	}

	cmd.Flags().VarP(&o.artifactType, "type", "t", `type of artifact to be pushed. Allowed values: "rule", "plugin"`)
	err := cmd.MarkFlagRequired("type")
	if err != nil {
		o.Printer.Error.Println("cannot mark type flag as required")
	}
	cmd.Flags().StringArrayVarP(&o.dependencies, "dependency", "d", []string{},
		"define a rule to plugin dependency. Example: '--dependency cloudtrail:1.2.3")

	return cmd
}

// RunPush executes the business logic for the push command.
func (o *pushOptions) RunPush(args []string) error {
	// pusher, err := ocipusher.NewPusher()
	// if err != nil {
	// 	o.Printer.Error.Println(err.Error())
	// 	return err
	// }

	// filename := args[0]
	// file, err := os.OpenFile(filepath.Clean(filename), 0, fs.FileMode(os.O_RDONLY))
	// if err != nil {
	// 	o.Printer.Error.Println(err.Error())
	// 	return err
	// }

	// fileContent, err := io.ReadAll(file)
	// if err != nil {
	// 	o.Printer.Error.Println(err.Error())
	// 	return err
	// }

	// // TODO: need validation!! ensure that tag is there, name of repo and so on!
	// ref := args[1]

	// res, err := pusher.Push(o.artifactType, fileContent, ref, filename, o.dependencies...)
	// if err != nil {
	// 	o.Printer.Error.Println(err.Error())
	// 	return err
	// }

	// o.Printer.DefaultText.Printf("Artifact pushed. Digest: %s\n", res.Digest)
	return nil
}
