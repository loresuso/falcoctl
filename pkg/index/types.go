package index

import (
	"io"

	"gopkg.in/yaml.v2"
)

type Dependency struct {
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Type       string `yaml:"type"`
}
type Entry struct {
	Name          string       `yaml:"name" jsonschema:"required"`
	PluginVersion string       `yaml:"pluginversion"`
	ApiVersion    string       `yaml:"apiversion"`
	Description   string       `yaml:"description"`
	Authors       string       `yaml:"authors"`
	Created       string       `yaml:"created"`
	Digest        string       `yaml:"digest"`
	Contact       string       `yaml:"contact"`
	License       string       `yaml:"license"`
	Artifact      string       `yaml:"artifact"`
	Keywords      []string     `yaml:"keywords"`
	Dependencies  []Dependency `yaml:"dependencies"`
}
type PluginIndex struct {
	ApiVersion string
	Parent     string
	Entries    []Entry
}

func LoadIndex(i *io.ReadCloser) (*PluginIndex, error) {
	decoder := yaml.NewDecoder(*i)
	index := &PluginIndex{}
	if err := decoder.Decode(index); err != nil {
		return nil, err
	}
	return index, nil
}
