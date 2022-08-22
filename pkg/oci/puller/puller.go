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

package puller

import (
	"encoding/json"
	"errors"
	"os"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
)

// Puller implements pull operations.
type Puller struct {
	Client *authn.Client
}

// NewPuller create a new puller that can be used for pull operations.
func NewPuller() (*Puller, error) {
	c, err := authn.NewClient()
	if err != nil {
		return nil, err
	}
	return &Puller{
		Client: c,
	}, nil
}

// Pull an artifact from a remote registry.
func (p *Puller) Pull(ref string) (*oci.RegistryResult, error) {
	registry := content.Registry{Resolver: p.Client.Resolver}
	memoryStore := content.NewMemory()

	allowedMediaTypes := []string{
		oci.FalcoRuleConfigMediaType,
		oci.FalcoRuleLayerMediaType,
		oci.FalcoPluginConfigMediaType,
		oci.FalcoPluginLayerMediaType,
	}

	var layers []v1.Descriptor
	desc, err := oras.Copy(p.Client.Context, registry, ref, memoryStore, "",
		oras.WithAllowedMediaTypes(allowedMediaTypes),
		oras.WithLayerDescriptors(func(l []v1.Descriptor) {
			layers = l
		}))
	if err != nil {
		return nil, err
	}

	var configData []byte
	var layerData []byte
	var ok bool

	for _, layer := range layers {
		switch layer.MediaType {
		case oci.FalcoPluginConfigMediaType, oci.FalcoRuleConfigMediaType:
			if _, configData, ok = memoryStore.Get(layer); !ok {
				return nil, errors.New("cannot get content of the config layer")
			}
		case oci.FalcoPluginLayerMediaType, oci.FalcoRuleLayerMediaType:
			if _, layerData, ok = memoryStore.Get(layer); !ok {
				return nil, errors.New("cannot get content of the principal layer")
			}
		}
	}

	var artifactConfig oci.ArtifactConfig
	err = json.Unmarshal(configData, &artifactConfig)
	if err != nil {
		return nil, err
	}

	file, err := os.Create(artifactConfig.Filename)
	if err != nil {
		return nil, err
	}

	_, err = file.Write(layerData)
	if err != nil {
		return nil, err
	}

	return &oci.RegistryResult{
		Config: artifactConfig,
		Digest: string(desc.Digest),
	}, nil
}
