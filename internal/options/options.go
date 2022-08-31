package options

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/falcosecurity/falcoctl/internal/store"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	version "github.com/falcosecurity/falcoctl/pkg/version"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Remote options struct.
type Remote struct {
	CACertFilePath    string
	PlainHTTP         bool
	Insecure          bool
	Configs           []string
	Username          string
	PasswordFromStdin bool
	Password          string
}

func (opts *Remote) NewRegistry(hostname string, common commonoptions.ConfigOptions) (reg *remote.Registry, err error) {
	reg, err = remote.NewRegistry(hostname)
	if err != nil {
		return nil, err
	}
	// reg.PlainHTTP = opts.isPlainHttp(reg.Reference.Registry)
	if reg.Client, err = opts.authClient(common.Verbose); err != nil {
		return nil, err
	}
	return
}

// authClient assembles a oras auth client.
func (opts *Remote) authClient(verbose bool) (client *auth.Client, err error) {
	// config, err := opts.tlsConfig()
	if err != nil {
		return nil, err
	}
	client = &auth.Client{
		Client: &http.Client{
			// default value are derived from http.DefaultTransport
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// TLSClientConfig:       config,
			},
		},
		Cache: auth.NewCache(),
	}
	client.SetUserAgent("falcoctl/" + version.NewVersion().SemVersion)

	cred := opts.Credential()
	if cred != auth.EmptyCredential {
		client.Credential = func(ctx context.Context, s string) (auth.Credential, error) {
			return cred, nil
		}
	} else {
		store, err := store.NewStore(opts.Configs...)
		if err != nil {
			return nil, err
		}
		client.Credential = store.Credential
	}
	return
}

// Credential returns a credential based on the remote options.
func (opts *Remote) Credential() auth.Credential {
	return auth.Credential{Username: opts.Username, Password: opts.Password}
}
