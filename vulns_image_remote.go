// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021-present Datadog, Inc.

package ddtrivy

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"

	trivycache "github.com/aquasecurity/trivy/pkg/cache"
	trivyartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact"
	trivyartifactimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// ScanImage launches a trivy scan on an image.
func ScanImage(ctx context.Context, artifactOpts trivyartifact.Option, trivyCache trivycache.Cache, image ftypes.Image) (*cdx.BOM, error) {
	trivyArtifact, err := trivyartifactimage.NewArtifact(image, trivyCache, artifactOpts)
	if err != nil {
		return nil, fmt.Errorf("ecr-image: could not create trivy image artifact: %w", err)
	}

	return doTrivyScan(ctx, trivyArtifact, trivyCache)
}
