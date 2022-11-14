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
	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	redirectUrl      = "http://localhost:3000/callback"
	callbackEndpoint = "/callback"
	callbackAddr     = ":3000"
	longOauth        = `Retrieve access and refresh tokens for OAuth2.0 authentication

With this command it is possible to interact with registries supporting OAuth2.0. 
Since each registry may have implemented all or a subset of possible authorization grants, for maximum flexibility 
falcoctl gives users the opportunity to choose among three different grant types, namely: 

- authorization_code
- client_credentials
- password

For more information about all these grant types, please visit:
https://www.rfc-editor.org/rfc/rfc6749#section-1.3

Example - Generate access and refresh tokens using "authorization_code" grant type (default):
	falcoctl registry oauth --auth-url="http://localhost:9096/authorize" \
		--token-url="http://localhost:9096/token" \
		--client-id="000000" \
		--client-secret="999999" \
		--scopes="my-scope" \
		-i

Example - Generate access and refresh tokens using "client_credentials" grant type:
	falcoctl registry oauth --grant-type="client_credentials" \
		--auth-url="http://localhost:9096/authorize" \
		--token-url="http://localhost:9096/token" \
		--client-id=000000 \
		--client-secret=999999  --scopes="my-scope"
		

Example - Generate access and refresh tokens using "password" grant type 
	falcoctl registry oauth --grant-type=password \
		--auth-url="http://localhost:9096/authorize" \
		--token-url="http://localhost:9096/token" \
		--scopes="my-scope"
The user will then be asked to enter its username and password to complete authentication. 
`
)

type oauthOptions struct {
	*options.CommonOptions
	grantType    string
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
		Long:                  longOauth,
		Args:                  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunOauth(ctx))
		},
	}

	cmd.Flags().StringVar(&o.grantType, "grant-type", "authorization_code", "type of OAuth2.0 flow to be used")

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
	switch o.grantType {
	case "authorization_code":
		return o.runOauthAuthCode(ctx)
	case "client_credentials":
		return o.runOauthClientCredentials(ctx)
	case "password":
		return o.runOauthPassword(ctx)
	default:
		return fmt.Errorf("unsupported grant type: %s", o.grantType)
	}
}

// runOauthAuthCode implements the authorization_code flow.
func (o *oauthOptions) runOauthAuthCode(ctx context.Context) error {
	conf := &oauth2.Config{
		ClientID:     o.clientId,
		ClientSecret: o.clientSecret,
		Scopes:       o.scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.authURL,
			TokenURL: o.tokenURL,
		},
		RedirectURL: redirectUrl,
	}

	statusChan := make(chan bool, 1)
	codeChan := make(chan string, 1)

	o.Printer.Spinner.Start("Retrieving tokens ...")

	// Prepare server for receiving the authorization code
	go func() {
		http.HandleFunc(callbackEndpoint, func(w http.ResponseWriter, r *http.Request) {
			code := r.URL.Query().Get("code")
			w.Write([]byte("Please, check your command line!"))
			if code != "" {
				statusChan <- true
				codeChan <- code
			} else {
				statusChan <- false
			}
		})
		o.Printer.CheckErr(http.ListenAndServe(callbackAddr, nil))
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

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("unable to exchange code for tokens: %w", err)
	}

	o.Printer.Spinner.Success("Access tokens correctly retrieved\n")

	o.Printer.DefaultText.Printfln("access token: %s, refresh token: %s",
		token.AccessToken, token.RefreshToken)

	return nil
}

// runOauthClientCredentials implements the client_credentials flow.
func (o *oauthOptions) runOauthClientCredentials(ctx context.Context) error {
	conf := clientcredentials.Config{
		ClientID:     o.clientId,
		ClientSecret: o.clientSecret,
		TokenURL:     o.tokenURL,
		Scopes:       o.scopes,
	}

	token, err := conf.Token(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve token: %w", err)
	}

	o.Printer.DefaultText.Printfln("access token: %s, refresh token: %s",
		token.AccessToken, token.RefreshToken)

	return nil
}

// runOauthPassword implements the password flow.
func (o *oauthOptions) runOauthPassword(ctx context.Context) error {
	username, password, err := utils.GetCredentials(o.Printer)
	if err != nil {
		return err
	}

	conf := oauth2.Config{
		ClientID:     o.clientId,
		ClientSecret: o.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  o.authURL,
			TokenURL: o.tokenURL,
		},
		RedirectURL: redirectUrl,
		Scopes:      nil,
	}

	token, err := conf.PasswordCredentialsToken(ctx, username, password)
	if err != nil {
		return fmt.Errorf("unable to retrieve token: %w", err)
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
