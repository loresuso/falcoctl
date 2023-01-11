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

package config

import (
	"path/filepath"
	"time"

	"github.com/docker/docker/pkg/homedir"
)

var (
	// ConfigDir configuration directory for falcoctl.
	ConfigDir string
	// FalcoctlPath path inside the configuration directory where the falcoctl stores its config files.
	FalcoctlPath string
	// IndexesFile name of the file where the indexes info is stored. It lives under FalcoctlPath.
	IndexesFile string
	// ClientCredentialsFile name of the file where oauth client credentials are stored. It lives under FalcoctlPath.
	ClientCredentialsFile string
)

const (
	// ConfigPath is the path to the default config
	ConfigPath = "/etc/falcoctl/config.yaml"
	// PluginsDir default path where plugins are installed.
	PluginsDir = "/usr/share/falco/plugins"
	// RulesfilesDir default path where rulesfiles are installed.
	RulesfilesDir = "/etc/falco"
	// FollowResync time interval how often it checks for newer version of the artifact.
	// Default values is set every 24 hours.
	FollowResync = time.Hour * 24
)

// Index represents a configured index
type Index struct {
	Name string `mapstructure:"name"`
	URL  string `mapstructure:"url"`
}

// Oauth represents an OAuth credential
type AuthOauth struct {
	Registry     string `mapstructure:"registry"`
	ClientSecret string `mapstructure:"client_secret"`
	ClientID     string `mapstructure:"client_id"`
	TokenURL     string `mapstructure:"token_url"`
}

// Basic represents a Basic credential
type AuthBasic struct {
	Registry string `mapstructure:"registry"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

// Follow represents the follower configuration
type Follow struct {
	Every string `mapstructure:"every"`
}

// Config represents the global config file for falcoctl
type Config struct {
	Indexes   []Index     `mapstructure:"indexes"`
	AuthOauth []AuthOauth `mapstructure:"authOauth"`
	AuthBasic []AuthBasic `mapstructure:"authBasic"`
	Follow    Follow      `mapstructure:"follow"`
}

func init() {
	ConfigDir = filepath.Join(homedir.Get(), ".config")
	FalcoctlPath = filepath.Join(ConfigDir, "falcoctl")
	IndexesFile = filepath.Join(FalcoctlPath, "indexes.yaml")
	ClientCredentialsFile = filepath.Join(FalcoctlPath, "clientcredentials.json")
}
