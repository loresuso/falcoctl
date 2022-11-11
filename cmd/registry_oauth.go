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
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"net/http"
	"os/exec"
	"runtime"
)

var longOauth = `Retrieve access and refresh tokens for OAuth2.0 authentication

Example - 
`

type oauthOptions struct {
	*options.CommonOptions
	authURL      string
	tokenURL     string
	clientId     string
	clientSecret string
	scopes       []string
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
	cmd.Flags().StringSliceVar(&o.scopes, "scopes", nil, "comma separeted list of scopes for which requesting access")
	if err := cmd.MarkFlagRequired("scopes"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"scopes\" as required")
		return nil
	}
	cmd.Flags().BoolVarP(&o.interactive, "interactive", "i", false, "interactively open web browser to login")

	return cmd
}

func (o *oauthOptions) RunOauth(ctx context.Context) error {
	conf := &oauth2.Config{
		ClientID:     o.clientId,
		ClientSecret: o.clientSecret,
		Scopes:       o.scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.authURL,
			TokenURL: o.tokenURL,
		},
		RedirectURL: "http://localhost:3000/login/github/callback",
	}

	statusChan := make(chan bool, 1)
	codeChan := make(chan string, 1)

	// Prepare server for receiving the authorization code
	go func() {
		http.HandleFunc("/login/github/callback", func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			w.Write([]byte("Please, check your command line!"))
			w.WriteHeader(http.StatusOK)
			if code != "" {
				statusChan <- true
				codeChan <- code
			} else {
				statusChan <- false
			}
		})
		o.Printer.CheckErr(http.ListenAndServe(":3000", nil))
	}()

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	if o.interactive {
		if err := openBrowser(url); err != nil {
			return fmt.Errorf("unable to open browser: %w", err)
		}
	} else {
		o.Printer.DefaultText.Printfln("Please, visit %s to authenticate", url)
	}

	if !<-statusChan {
		return fmt.Errorf("Received invalid or nil code, exiting")
	}
	code := <-codeChan

	o.Printer.Info.Printfln("Received code: %s", code)

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("unable to exchange code for tokens: %w", err)
	}

	o.Printer.DefaultText.Printfln("access token: %s, refresh token: %s",
		token.AccessToken, token.RefreshToken)

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
