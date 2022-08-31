// // Copyright 2022 The Falco Authors
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //      http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package pusher

// import (
// 	"encoding/json"
// 	"path/filepath"

// 	"oras.land/oras-go/pkg/content"
// 	"oras.land/oras-go/pkg/oras"

// 	"github.com/falcosecurity/falcoctl/pkg/oci"
// 	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
// )

// // Pusher implements push operations.
// type Pusher struct {
// 	Client *authn.Client
// }

// // NewPusher create a new pusher that can be used for push operations.
// func NewPusher() (*Pusher, error) {
// 	c, err := authn.NewClient()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &Pusher{
// 		Client: c,
// 	}, nil
// }

// // Push an artifact to a remote registry.
// func (p *Pusher) Push(artifactType oci.ArtifactType, data []byte, ref, filename string, dependencies ...string) (*oci.RegistryResult, error) {
// 	var configMediaType string
// 	var layerMediaType string

// 	if artifactType == oci.Rule {
// 		configMediaType = oci.FalcoRuleConfigMediaType
// 		layerMediaType = oci.FalcoRuleLayerMediaType
// 	} else {
// 		configMediaType = oci.FalcoPluginConfigMediaType
// 		layerMediaType = oci.FalcoPluginLayerMediaType
// 	}

// 	memoryStore := content.NewMemory()
// 	filename = filepath.Base(filename)
// 	desc, err := memoryStore.Add(filename, layerMediaType, data)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create config and fill common fields of the config.
// 	artifactConfig := oci.ArtifactConfig{Filename: filename}

// 	// Fill artifact specific fields.
// 	switch artifactType {
// 	case oci.Rule:
// 		if err = artifactConfig.SetRequiredPluginVersions(dependencies...); err != nil {
// 			return nil, err
// 		}
// 	case oci.Plugin:
// 	}

// 	configData, err := json.Marshal(artifactConfig)
// 	if err != nil {
// 		return nil, err
// 	}

// 	configDesc, err := memoryStore.Add("", configMediaType, configData)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create manifest.
// 	manifest, manifestDesc, err := content.GenerateManifest(&configDesc, nil, desc)
// 	if err != nil {
// 		return nil, err
// 	}
// 	err = memoryStore.StoreManifest(ref, manifestDesc, manifest)
// 	if err != nil {
// 		return nil, err
// 	}

// 	registry := content.Registry{Resolver: p.Client.Resolver}

// 	desc, err = oras.Copy(p.Client.Context, memoryStore, ref, registry, "")
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &oci.RegistryResult{
// 		Config: artifactConfig,
// 		Digest: string(desc.Digest),
// 	}, nil
// }
