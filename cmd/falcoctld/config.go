package main

type Auth struct {
	Registry string `yaml:"registry"`
	User     string `yaml:"user"`
	Token    string `yaml:"token"`
	AuthType string `yaml:"type"`
}

type Index struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
}

type Artifact struct {
	Name   string `yaml:"name"`
	Follow bool   `yaml:"follow"`
}

type Config struct {
	Auths         []Auth     `yaml:"auths"`
	Indexes       []Index    `yaml:"indexes"`
	Artifacts     []Artifact `yaml:"artifacts"`
	PluginsDir    string     `yaml:"pluginsdir"`
	RulesfilesDir string     `yaml:"rulesfilesdir"`
	PlainHTTP     bool       `yaml:"plainhttp"`
	Oauth         bool       `yaml:"oauth"`
}
