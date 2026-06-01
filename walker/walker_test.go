// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build trivy

// Package walker holds the trivy walkers
package walker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestFS_Walk(t *testing.T) {
	tests := []struct {
		name      string
		option    walker.Option
		rootDir   string
		analyzeFn walker.WalkFunc
		wantErr   string
	}{
		{
			name:    "happy path",
			rootDir: "testdata/fs",
			analyzeFn: func(_ context.Context, filePath string, _ os.FileInfo, opener analyzer.Opener) error {
				if filePath == "bar" {
					got, err := opener()
					require.NoError(t, err)

					b, err := io.ReadAll(got)
					require.NoError(t, err)

					assert.Equal(t, "bar\n", string(b))
				}
				return nil
			},
		},
		{
			name:    "skip file",
			rootDir: "testdata/fs",
			option: walker.Option{
				SkipFiles: []string{"bar"},
			},
			analyzeFn: func(_ context.Context, filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if filePath == "bar" {
					assert.Fail(t, "skip files error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "skip dir",
			rootDir: "testdata/fs/",
			option: walker.Option{
				SkipDirs: []string{"/app"},
			},
			analyzeFn: func(_ context.Context, filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if strings.Contains(filePath, "app") {
					assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "sad path",
			rootDir: "testdata/fs",
			analyzeFn: func(context.Context, string, os.FileInfo, analyzer.Opener) error {
				return errors.New("error")
			},
			wantErr: "failed to analyze file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewFSWalker()
			err := w.Walk(context.TODO(), tt.rootDir, tt.option, tt.analyzeFn)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFS_Walk_SkipInstalledFiles(t *testing.T) {
	const owned = "usr/lib64/libowned.so"
	const unowned = "opt/app/unowned"

	root := t.TempDir()
	for _, rel := range []string{owned, unowned} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte("x"), 0o755)) // exec bit, like a real .so/binary
	}

	visit := func(skip map[string]struct{}) map[string]bool {
		visited := map[string]bool{}
		err := NewFSWalkerWithInstalledFiles(skip).Walk(context.TODO(), root, walker.Option{}, func(_ context.Context, filePath string, _ os.FileInfo, _ analyzer.Opener) error {
			visited[filePath] = true
			return nil
		})
		require.NoError(t, err)
		return visited
	}

	// A listed file is skipped before analysis; an unlisted one is still visited.
	got := visit(map[string]struct{}{owned: {}})
	assert.False(t, got[owned], "listed file must be skipped")
	assert.True(t, got[unowned], "unlisted file must be visited")

	// Keys are matched root-relative: a leading "/" must not match, so the file
	// is visited (which also confirms it is otherwise reachable).
	leading := visit(map[string]struct{}{"/" + owned: {}})
	assert.True(t, leading[owned], "leading-slash key must not match the walk path")
}
