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

package pusher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opencontainers/image-spec/specs-go"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	logger "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

var (
	ErrNotFound = errNotFound()
)

func errNotFound() error { return errors.New("index not found") }

// Pusher implements push operations.
type Pusher struct {
	Client    *auth.Client
	fileStore *file.Store
}

// NewPusher create a new pusher that can be used for push operations.
func NewPusher(ctx context.Context, client *auth.Client) (*Pusher, error) {
	return &Pusher{
		Client:    client,
		fileStore: file.New(""),
	}, nil
}

// Push an artifact to a remote registry.
// artifactType can be either a rule or plugin.
// artifactPath path of the artifact blob on the disk.
// ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
// dependencies rule to plugin dependency expressed as pluginName:version. Ex. cloudtrail:1.2.3.
func (p *Pusher) Push(ctx context.Context, artifactType oci.ArtifactType,
	artifactPath, ref, platform string, dependencies ...string) (*oci.RegistryResult, error) {
	var dataDesc, configDesc, manifestDesc, rootDesc *v1.Descriptor
	var err error

	// Create the object to interact with the remote repo.
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	repo.Client = p.Client

	// Prepare data layer.
	if dataDesc, err = p.storeMainLayer(ctx, artifactType, artifactPath); err != nil {
		return nil, err
	}

	// Prepare configuration layer.
	if configDesc, err = p.storeConfigLayer(ctx, artifactType, dependencies); err != nil {
		return nil, err
	}

	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	if manifestDesc, err = p.packManifest(ctx, configDesc, dataDesc, platform); err != nil {
		return nil, err
	}

	if rootDesc, err = p.packIndex(ctx, artifactType, *manifestDesc, repo); err != nil {
		return nil, err
	}

	// Tag the manifest desc locally.
	if err = p.fileStore.Tag(ctx, *rootDesc, repo.Reference.Reference); err != nil {
		return nil, err
	}
	_, err = oras.Copy(ctx, p.fileStore, repo.Reference.Reference, repo, "", oras.DefaultCopyOptions)
	if err != nil {
		return nil, err
	}

	// Todo(loresuso, alacuku): not sure what to return. The manifest itself could be enough since it holds useful data.
	return &oci.RegistryResult{
		Digest: string(manifestDesc.Digest),
	}, nil
}

func (p *Pusher) retrieveIndex(ctx context.Context, repo *remote.Repository) (*v1.Index, error) {
	memoryStore := memory.New()
	ref := repo.Reference.String()
	indexDesc, err := oras.Copy(ctx, repo, repo.Reference.Reference, memoryStore, "", oras.DefaultCopyOptions)
	if err != nil {
		if strings.Contains(err.Error(), fmt.Sprintf("%s: not found", repo.Reference.Reference)) {
			return nil, fmt.Errorf("unable to download image index for ref %s, %w", ref, ErrNotFound)
		}
		return nil, fmt.Errorf("unable to download image index for ref %s: %w", ref, err)
	}

	// Check if the descriptor has media type image index.
	if indexDesc.MediaType != v1.MediaTypeImageIndex {
		return nil, fmt.Errorf("the pulled descriptor for ref %q has media type %q while expecting %q",
			ref, indexDesc.MediaType, v1.MediaTypeImageIndex)
	}

	var index v1.Index
	reader, err := memoryStore.Fetch(ctx, indexDesc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch index from memory store for ref %q: %w", ref, err)
	}
	var indexBytes = []byte{}

	if indexBytes, err = io.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("unable to read index from reader for ref %q: %w", ref, err)
	}

	if err = json.Unmarshal(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("unable to unmarshal index for ref %q: %w", ref, err)
	}
	return &index, nil
}

func (p *Pusher) updateIndex(ctx context.Context, indexDesc v1.Index, manifestDesc v1.Descriptor, repo *remote.Repository) (*v1.Index, error) {
	memoryStore := memory.New()
	ref := repo.Reference

	// Check if the index already contains the manifest for the given platform.
	for i, m := range indexDesc.Manifests {
		// If we find a manifest in the index that has the same platform as the artifact that we are currently
		// processing it means that we are going to overwrite it with the current version. Only if the digests are
		// different.
		if reflect.DeepEqual(m.Platform, manifestDesc.Platform) &&
			m.Digest.String() != manifestDesc.Digest.String() {
			ref.Reference = m.Digest.String()
			remoteManifestDesc, err := oras.Copy(ctx, repo, m.Digest.String(), memoryStore, "", oras.DefaultCopyOptions)
			if err != nil {
				if !strings.Contains(err.Error(), fmt.Sprintf("%s: not found", repo.Reference.Reference)) {
					return nil, fmt.Errorf("unable to download blob for ref %s: %w", ref, err)
				}
			}

			var manifest v1.Manifest
			reader, err := memoryStore.Fetch(ctx, remoteManifestDesc)
			if err != nil {
				return nil, fmt.Errorf("unable to fetch remote manifest desck from memory store for ref %q: %w", ref, err)
			}
			var manifestBytes = []byte{}

			if manifestBytes, err = io.ReadAll(reader); err != nil {
				return nil, fmt.Errorf("unable to read manifest from reader for ref %q: %w", ref, err)
			}

			if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
				return nil, fmt.Errorf("unable to unmarshal manifest for ref %q: %w", ref, err)
			}

			// Here we delete the existing artifact in the remote repository.
			// TODO(alacuku, loresuso): check if the error is not found and in that case do not error(maybe a warning).
			// TODO(alacuku, loresuso): should we delete the artifact or just leave it there and update the manifest to point to the new version
			if err := repo.Delete(ctx, manifest.Layers[0]); err != nil {
				return nil, fmt.Errorf("unable to delete artifact with digest %q and ref %q from remote repo: %w", manifest.Layers[0].Digest.String(), ref, err)
			}

			if err := repo.Delete(ctx, manifest.Config); err != nil {
				return nil, fmt.Errorf("unable to delete artifact with digest %q and ref %q from remote repo: %w", manifest.Config.Digest.String(), ref, err)
			}
			// Remove manifest of the deleted artifact from the manifest.
			indexDesc.Manifests = append(indexDesc.Manifests[:i], indexDesc.Manifests[i+1:]...)
			break
		}
	}
	indexDesc.Manifests = append(indexDesc.Manifests, manifestDesc)
	return &indexDesc, nil
}

func (p *Pusher) storeMainLayer(ctx context.Context, artifactType oci.ArtifactType, artifactPath string) (*v1.Descriptor, error) {
	var layerMediaType string

	switch artifactType {
	case oci.Rule:
		layerMediaType = oci.FalcoRuleLayerMediaType
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginLayerMediaType
	}

	// Add the content of the principal layer to the file store.
	desc, err := p.fileStore.Add(ctx, filepath.Clean(artifactPath), layerMediaType, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("unable to store artifact %s of type %s: %w", artifactPath, artifactType, err)
	}

	return &desc, nil
}

func (p *Pusher) storeConfigLayer(ctx context.Context, artifactType oci.ArtifactType, dependencies []string) (*v1.Descriptor, error) {
	var layerMediaType string
	// Create config and fill common fields of the config (empty for now).
	artifactConfig := oci.ArtifactConfig{}

	switch artifactType {
	case oci.Rule:
		layerMediaType = oci.FalcoRuleConfigMediaType
		if err := artifactConfig.SetRequiredPluginVersions(dependencies...); err != nil {
			return nil, fmt.Errorf("unable to set dependencies %s: %w", dependencies, err)
		}
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginConfigMediaType
	}

	return p.toFileStore(ctx, layerMediaType, "config", artifactConfig)
}

func (p *Pusher) toFileStore(ctx context.Context, mediaType, name string, data interface{}) (*v1.Descriptor, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal data of media type %q: %w", mediaType, err)
	}

	// Create temporary common file. This is needed because we have to add it to the store.
	configFile, err := os.CreateTemp("", "falcoctl")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := configFile.Close(); err != nil {
			logger.Printf("Error closing file: %s\n", err)
		}
	}()

	if _, err := configFile.Write(dataBytes); err != nil {
		return nil, fmt.Errorf("unable to write data of media type %q to temporary file %s: %w", mediaType, configFile.Name(), err)
	}

	desc, err := p.fileStore.Add(ctx, name, mediaType, filepath.Clean(configFile.Name()))
	if err != nil {
		return nil, fmt.Errorf("unable to store data of media type %q in the file store: %w", mediaType, err)
	}
	return &desc, nil
}

func (p *Pusher) packManifest(ctx context.Context, configDesc, dataDesc *v1.Descriptor, platform string) (*v1.Descriptor, error) {
	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	packOptions := oras.PackOptions{ConfigDescriptor: configDesc}
	desc, err := oras.Pack(ctx, p.fileStore, []v1.Descriptor{*dataDesc}, packOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to generate manifest for config layer %s and data layer %s: %w", configDesc.MediaType, dataDesc.MediaType, err)
	}

	if dataDesc.MediaType == oci.FalcoPluginLayerMediaType {
		tokens := strings.Split(platform, ":")
		desc.Platform = &v1.Platform{
			OS:           tokens[0],
			Architecture: tokens[1],
		}
	}

	return &desc, nil
}

func (p *Pusher) packIndex(ctx context.Context, artifactType oci.ArtifactType, manifestDesc v1.Descriptor, repo *remote.Repository) (*v1.Descriptor, error) {
	ref := repo.Reference.String()

	// If we are handling an artifact of type "plugin" then we need to pull the image
	// index (https://github.com/opencontainers/image-spec/blob/main/image-index.md)
	if artifactType == oci.Plugin {
		index, err := p.retrieveIndex(ctx, repo)
		// In case of error return.
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("unable to retrieve index with ref %q from remote repo: %w", ref, err)
		}

		// If not index is present than create one.
		if errors.Is(err, ErrNotFound) {
			index = &v1.Index{
				Versioned: specs.Versioned{2},
				MediaType: v1.MediaTypeImageIndex,
			}
		}

		// todo: check the parameters passed to updateIndex. reference or copy?
		if index, err = p.updateIndex(ctx, *index, manifestDesc, repo); err != nil {
			return nil, err
		}
		newIndexDesc, err := p.toFileStore(ctx, v1.MediaTypeImageIndex, "index", index)
		if err != nil {
			return nil, fmt.Errorf("unable to add index content to the file store: %w", err)
		}
		return newIndexDesc, nil
	}
	return &manifestDesc, nil
}
