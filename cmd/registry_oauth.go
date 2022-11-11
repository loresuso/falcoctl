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
	"os/exec"
	"runtime"

	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/spf13/cobra"
)

type oauthOptions struct {
	*options.CommonOptions
	authURL      string
	tokenURL     string
	clientId     string
	clientSecret string
	interactive  bool
}

func NewOauthCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := oauthOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "oauth",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve access and refresh tokens for OAuth2.0 authentication",
		Long:                  "Retrieve access and refresh tokens for OAuth2.0 authentication",
		Args:                  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunOauth(ctx))
		},
	}

	cmd.Flags().StringVar(&o.authURL, "auth-url", "", "auth URL used to get OAuth2.0 authorization code")
	if err := cmd.MarkFlagRequired("auth-url"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"auth-url\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.tokenURL, "token-url", "", "token URL used to get access and refresh tokens")
	if err := cmd.MarkFlagRequired("token-url"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"token-url\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.clientId, "client-id", "", "client ID of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-id"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-id\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.clientSecret, "client-secret", "", "client secret of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-secret"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-secret\" as required")
		return nil
	}
	cmd.Flags().BoolVarP(&o.interactive, "interactive", "i", false, "interactively open web browser to login")

	return cmd
}

func (o *oauthOptions) RunOauth(context.Context) error {

	return nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
