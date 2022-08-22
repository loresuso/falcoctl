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

package authn

import (
	"context"
	"net/http"

	"github.com/containerd/containerd/remotes"
	"oras.land/oras-go/pkg/auth"
	"oras.land/oras-go/pkg/auth/docker"
)

const (
	falcoctlUserAgent = "falcoctl"
)

// Client is used to interact with a remote registry.
type Client struct {
	Context    context.Context
	Authorizer auth.Client
	Resolver   remotes.Resolver
}

// NewClient creates a new Client for remote registry.
func NewClient() (*Client, error) {
	c := &Client{}

	c.Context = context.Background()

	// Authentication credentials will be stored in $HOME/.docker/config.json
	authClient, err := docker.NewClientWithDockerFallback()
	if err != nil {
		return nil, err
	}
	c.Authorizer = authClient

	headers := http.Header{}
	headers.Set("User-Agent", falcoctlUserAgent)
	opts := []auth.ResolverOption{auth.WithResolverHeaders(headers)}
	resolver, err := c.Authorizer.ResolverWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	c.Resolver = resolver

	return c, nil
}

// Login to remote registry.
// For now, only support login with token.
func (c *Client) Login(hostname, user, token string) error {
	loginOptions := []auth.LoginOption{
		auth.WithLoginContext(c.Context),
		auth.WithLoginHostname(hostname),
		auth.WithLoginUsername(user),
		auth.WithLoginSecret(token),
	}
	err := c.Authorizer.LoginWithOpts(
		loginOptions...,
	)

	return err
}

// Logout from remote registry.
func (c *Client) Logout(hostname string) error {
	return c.Authorizer.Logout(c.Context, hostname)
}
