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
	"bufio"
	"errors"
	"fmt"
	"os"

	"github.com/moby/term"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/falcosecurity/falcoctl/internal/options"
	"github.com/falcosecurity/falcoctl/internal/store"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type loginOptions struct {
	*commonoptions.ConfigOptions
	options.Remote
	Hostname string
}

func (o *loginOptions) Validate(args []string) error {
	if len(args) != 0 {
		o.Hostname = args[0]
	} else {
		o.Hostname = oci.DefaultRegistry
	}
	return nil
}

func (o *loginOptions) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&o.Username, "user", "u", "", "The login username")
	flags.StringVarP(&o.Username, "password", "p", "", "The login password")
	flags.BoolVar(&o.PasswordFromStdin, "password-from-stdin", false, "Whether to retrieve the password from stdin or not")
	// TODO: fill other flags later.
}

// NewLoginCmd returns the login command.
func NewLoginCmd(opt *commonoptions.ConfigOptions) *cobra.Command {
	o := loginOptions{
		ConfigOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "login hostname",
		DisableFlagsInUseLine: true,
		Short:                 "Login to an OCI registry",
		Long:                  "Login to an OCI registry to push and pull Falco rules and plugins",
		Args:                  cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			output.ExitOnErr(o.RunLogin(args))
		},
	}

	o.AddFlags(cmd.Flags())

	return cmd
}

// RunLogin executes the business logic for the login command.
func (o *loginOptions) RunLogin(args []string) error {

	var user, password string
	var err error
	if o.Username == "" {
		if user, err = readLine("Username: ", false); err != nil {
			return err
		}
	}

	if o.Password == "" && o.PasswordFromStdin {
		if password, err = readLine("Password: ", true); err != nil {
			return err
		}
	} else {
		return errors.New("Password must be non empty")
	}

	o.Username = user
	o.Password = password

	// Store the validated credential
	store, err := store.NewStore("")
	if err != nil {
		return err
	}
	if err := store.Store(o.Hostname, o.Credential()); err != nil {
		return err
	}

	o.Printer.DefaultText.Println("Login succeeded")
	return nil
}

func readLine(prompt string, slient bool) (string, error) {
	fmt.Print(prompt)
	if slient {
		fd := os.Stdin.Fd()
		state, err := term.SaveState(fd)
		if err != nil {
			return "", err
		}
		term.DisableEcho(fd, state)
		defer term.RestoreTerminal(fd, state)
	}

	reader := bufio.NewReader(os.Stdin)
	line, _, err := reader.ReadLine()
	if err != nil {
		return "", err
	}
	if slient {
		fmt.Println()
	}

	return string(line), nil
}
