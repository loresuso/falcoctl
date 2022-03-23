package index

import (
	"github.com/go-playground/validator/v10"
	"io"

	"gopkg.in/yaml.v2"
)

//TODO complete struct tagging for validation purposes
type Dependency struct {
	Name       string `yaml:"name" validate:"required"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Type       string `yaml:"type"`
}
type Entry struct {
	Name          string       `yaml:"name" validate:"required"`
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
	Dependencies  []Dependency `yaml:"dependencies" validate:"dive"`
}
type PluginIndex struct {
	ApiVersion string  `yaml:"api_version" validate:"required"`
	Parent     string  `yaml:"parent"`
	Entries    []Entry `yaml:"entries" validate:"required,dive"`
}

func LoadIndex(i *io.ReadCloser) (*PluginIndex, error) {
	decoder := yaml.NewDecoder(*i)
	index := &PluginIndex{}
	if err := decoder.Decode(index); err != nil {
		return nil, err
	}
	return index, nil
}

var validate *validator.Validate

func ValidateIndex(data []byte) (*PluginIndex, error) {
	tmp := &PluginIndex{}
	err := yaml.Unmarshal(data, tmp)
	if err != nil {
		return nil, err
	}
	validate = validator.New()
	err = validate.Struct(tmp)
	if err != nil {
		return nil, err
	}
	return tmp, nil
}
