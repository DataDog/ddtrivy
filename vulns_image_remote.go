package ddtrivy

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-agentless-scanner/pkg/log"
	"github.com/DataDog/datadog-agentless-scanner/pkg/oci"
	"github.com/DataDog/datadog-agentless-scanner/pkg/types"
	ddogstatsd "github.com/DataDog/datadog-go/v5/statsd"

	trivycache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	trivyartifactimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

	v1name "github.com/google/go-containerregistry/pkg/name"
	v1image "github.com/google/go-containerregistry/pkg/v1"
	v1remote "github.com/google/go-containerregistry/pkg/v1/remote"
)

// LaunchTrivyRemoteImage launches a trivy scan on an image.
func LaunchTrivyRemoteImage(ctx context.Context, sc *types.ScannerConfig, statsd ddogstatsd.ClientInterface, opts types.ScannerOptions, artifactOpts artifact.Option) (*types.ScanResultVulns, error) {
	provider := opts.Scan.TargetID.Provider()
	switch opts.Scan.Type {
	case types.TaskTypeECRImage, types.TaskTypeLambda:
		if provider != types.CloudProviderAWS {
			return nil, fmt.Errorf("image: provider should be %q but %q was provided", types.CloudProviderAWS, provider)
		}
		return launchTrivyRemoteImage(ctx, sc, statsd, opts, artifactOpts)
	default:
		return nil, fmt.Errorf("image: unsupported scan for %q / %q", provider, opts.Entity.Type)
	}
}

func launchTrivyRemoteImage(ctx context.Context, sc *types.ScannerConfig, statsd ddogstatsd.ClientInterface, opts types.ScannerOptions, artifactOpts artifact.Option) (*types.ScanResultVulns, error) {
	remoteImageURL := opts.Entity.RemoteURL()
	log.Debugf("%s: creating new container image for %s", opts.Scan, remoteImageURL)

	ref, err := v1name.ParseReference(remoteImageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the image name: %w", err)
	}

	desc, err := oci.RemoteGet(ctx, ref)
	if err != nil {
		return nil, err
	}

	trivyImage, err := newRemoteContainerImageArtifact(remoteImageURL, ref, desc)
	if err != nil {
		return nil, fmt.Errorf("ecr-image: could not create trivy image: %w", err)
	}

	var trivyCache interface {
		trivycache.LocalArtifactCache
		trivycache.ArtifactCache
	}
	if sc.ScanCacheDisabled {
		trivyCache = trivycache.NewMemoryCache()
	} else {
		trivyCache = loadTrivyFSCache(statsd)
	}
	trivyArtifact, err := trivyartifactimage.NewArtifact(trivyImage, trivyCache, artifactOpts)
	if err != nil {
		return nil, fmt.Errorf("ecr-image: could not create trivy image artifact: %w", err)
	}

	result, err := doTrivyScan(ctx, opts, trivyArtifact, trivyCache)
	if err != nil && errors.Is(err, tar.ErrHeader) {
		// NOTE(pierrot): some layers may not have a valid tar header, because
		// they actually are not tar archives. In which case we just ignore the
		// error and do not report anything.
		return nil, fmt.Errorf("ecr-image: %w: %w", types.ErrCloudResourceNotFound, err)
	}
	return result, err
}

// -------------------------------------------------------------------------
// --- BEGIN: copied from trivy/pkg/fanal/artifact/image/container_image.go

func newRemoteContainerImageArtifact(imageName string, ref v1name.Reference, desc *v1remote.Descriptor) (ftypes.Image, error) {
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	return remoteImage{
		name:       imageName,
		Image:      img,
		ref:        implicitReference{ref: ref},
		descriptor: desc,
	}, nil
}

type remoteImage struct {
	name       string
	ref        implicitReference
	descriptor *v1remote.Descriptor
	v1image.Image
}

func (img remoteImage) Name() string {
	return img.name
}

func (img remoteImage) ID() (string, error) {
	h, err := img.ConfigName()
	if err != nil {
		return "", fmt.Errorf("unable to get the image ID: %w", err)
	}
	return h.String(), nil
}

func (img remoteImage) RepoTags() []string {
	tag := img.ref.TagName()
	if tag == "" {
		return []string{}
	}
	return []string{fmt.Sprintf("%s:%s", img.ref.RepositoryName(), tag)}
}

func (img remoteImage) RepoDigests() []string {
	repoDigest := fmt.Sprintf("%s@%s", img.ref.RepositoryName(), img.descriptor.Digest.String())
	return []string{repoDigest}
}

type implicitReference struct {
	ref v1name.Reference
}

func (r implicitReference) TagName() string {
	if t, ok := r.ref.(v1name.Tag); ok {
		return t.TagStr()
	}
	return ""
}

func (r implicitReference) RepositoryName() string {
	ctx := r.ref.Context()
	reg := ctx.RegistryStr()
	repo := ctx.RepositoryStr()
	// Default registry
	if reg != v1name.DefaultRegistry {
		return fmt.Sprintf("%s/%s", reg, repo)
	}
	// Trim default namespace
	// See https://docs.docker.com/docker-hub/official_repos
	return strings.TrimPrefix(repo, "library/")
}

// -------------------------------------------------------------------------
// --- END
