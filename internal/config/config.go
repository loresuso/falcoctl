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
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/docker/docker/pkg/homedir"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
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
	// EnvPrefix is the prefix for all the environment variables.
	EnvPrefix = "FALCOCTL"
	// ConfigPath is the path to the default config.
	ConfigPath = "/etc/falcoctl/config.yaml"
	// PluginsDir default path where plugins are installed.
	PluginsDir = "/usr/share/falco/plugins"
	// RulesfilesDir default path where rulesfiles are installed.
	RulesfilesDir = "/etc/falco"
	// FollowResync time interval how often it checks for newer version of the artifact.
	// Default values is set every 24 hours.
	FollowResync = time.Hour * 24

	oauthAuthKey = "oauthauths"
)

// Index represents a configured index.
type Index struct {
	Name string `mapstructure:"name"`
	URL  string `mapstructure:"url"`
}

// Oauth represents an OAuth credential.
type OauthAuth struct {
	Registry     string `mapstructure:"registry"`
	ClientSecret string `mapstructure:"clientSecret"`
	ClientID     string `mapstructure:"clientID"`
	TokenURL     string `mapstructure:"tokenURL"`
}

// Basic represents a Basic credential.
type BasicAuth struct {
	Registry string `mapstructure:"registry"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

// Follow represents the follower configuration.
type Follow struct {
	Every string `mapstructure:"every"`
}

// Config represents the global config file for falcoctl.
type Config struct {
	Indexes    []Index     `mapstructure:"indexes"`
	OauthAuths []OauthAuth `mapstructure:"OauthAuths"`
	BasicAuths []BasicAuth `mapstructure:"basicAuths"`
	Follow     Follow      `mapstructure:"follow"`
}

func init() {
	ConfigDir = filepath.Join(homedir.Get(), ".config")
	FalcoctlPath = filepath.Join(ConfigDir, "falcoctl")
	IndexesFile = filepath.Join(FalcoctlPath, "indexes.yaml")
	ClientCredentialsFile = filepath.Join(FalcoctlPath, "clientcredentials.json")
}

func Load(path string) error {
	viper.SetConfigName("config")

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	viper.AddConfigPath(filepath.Dir(absolutePath))
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("config: error reading config file: %w", err)
	}

	viper.SetEnvPrefix(EnvPrefix)

	// Environment variables can't have dashes in them, so bind them to their equivalent
	// keys with underscores.
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Bind to environment variables.
	viper.AutomaticEnv()

	return nil
}

func Indexes() ([]Index, error) {
	indexes := []Index{}

	if err := viper.UnmarshalKey("indexes", &indexes, viper.DecodeHook(indexListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get indexes: %w", err)
	}

	return indexes, nil
}

// indexListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "falcosecurity,https://falcosecurity.github.io/falcoctl/index.yaml;myindex,url"
func indexListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]Index{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []Index{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			indexes := make([]Index, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				indexes[i] = Index{
					Name: values[0],
					URL:  values[1],
				}
			}
			return indexes, nil
		case reflect.Slice:
			config := Config{}
			if err := mapstructure.WeakDecode(data, &config.Indexes); err != nil {
				return err, nil
			}
			return config.Indexes, nil
		default:
			return nil, nil
		}
	}
}

func BasicAuths() ([]BasicAuth, error) {
	auths := []BasicAuth{}

	if err := viper.UnmarshalKey("basicAuths", &auths, viper.DecodeHook(basicAuthListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get basicAuths: %w", err)
	}

	return auths, nil
}

// basicAuthListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "registry,username,password;registry1,username1,password1".
func basicAuthListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]BasicAuth{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []BasicAuth{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			auths := make([]BasicAuth, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				auths[i] = BasicAuth{
					Registry: values[0],
					User:     values[1],
					Password: values[2],
				}
			}
			return auths, nil
		case reflect.Slice:
			config := Config{}
			if err := mapstructure.WeakDecode(data, &config.BasicAuths); err != nil {
				return err, nil
			}
			return config.BasicAuths, nil
		default:
			return nil, nil
		}
	}
}


func OauthAuths() ([]OauthAuth, error) {
	auths := []OauthAuth{}

	if err := viper.UnmarshalKey(oauthAuthKey, &auths, viper.DecodeHook(oathAuthListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get oauthAuths: %w", err)
	}

	return auths, nil
}

// oauthAuthListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
//"registry,clientID,clientSecret,tokenURL;registry1,clientID1,clientSecret1,tokenURL1".
func oathAuthListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]OauthAuth{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []OauthAuth{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			auths := make([]OauthAuth, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				auths[i] = OauthAuth{
					Registry:     values[0],
					ClientID:     values[1],
					ClientSecret: values[2],
					TokenURL:     values[3],
				}
			}
			return auths, nil
		case reflect.Slice:
			var auths []OauthAuth
			if err := mapstructure.WeakDecode(data, &auths); err != nil {
				return err, nil
			}
			return auths, nil
		default:
			return nil, nil
		}
	}
}
