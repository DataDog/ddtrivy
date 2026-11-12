// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package walker holds the trivy walkers
package walker

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
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
			w := NewFSWalker(tt.rootDir)
			err := w.Walk(context.TODO(), tt.rootDir, tt.option, tt.analyzeFn)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFS_WalkContextDone(t *testing.T) {
	tests := []struct {
		name       string
		rootDir    string
		option     walker.Option
		cancelled  bool
		wantVisits int
	}{
		{
			name:       "directory",
			rootDir:    "testdata/fs",
			wantVisits: 1,
		},
		{
			name:    "directory with lenient error callback",
			rootDir: "testdata/fs",
			option: walker.Option{
				ErrorCallback: func(string, error) error { return nil },
			},
			wantVisits: 1,
		},
		{
			name:      "single file",
			rootDir:   "testdata/fs/bar",
			cancelled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelled {
				cancel()
			}

			visits := 0
			err := NewFSWalker(tt.rootDir).Walk(ctx, tt.rootDir, tt.option, func(context.Context, string, os.FileInfo, analyzer.Opener) error {
				visits++
				cancel()
				return nil
			})
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, tt.wantVisits, visits)
		})
	}
}

// TestFS_WalkTree walks trees made in a test directory and checks the files
// it reports, read through the opener.
func TestFS_WalkTree(t *testing.T) {
	tests := []struct {
		name   string
		files  []string          // slash-separated, relative to the test directory
		links  map[string]string // name to target
		root   string            // walk root, relative to the test directory
		option walker.Option
		want   []string
	}{
		{
			name:  "Latin-1 directory",
			files: []string{"opt/app/caf\xe9/readme.txt", "opt/app/lib/x.txt"},
			want:  []string{"opt/app/caf\xe9/readme.txt", "opt/app/lib/x.txt"},
		},
		{
			name:  "root is a link",
			files: []string{"tree/a.txt"},
			links: map[string]string{"link": "tree"},
			root:  "link",
			want:  []string{"a.txt"},
		},
		{
			name:  "links in the tree",
			files: []string{"dir/a.txt", "file.txt"},
			links: map[string]string{"dirlink": "dir", "filelink": "file.txt"},
			want:  []string{"dir/a.txt", "file.txt"},
		},
		{
			name:   "only dirs",
			files:  []string{"opt/a/b.txt", "usr/include/c.h", "var/lib/dpkg/info/x.md5sums", "var/lib/dpkg/status"},
			option: walker.Option{OnlyDirs: []string{"var/lib/dpkg/*", "opt/**"}},
			want:   []string{"opt/a/b.txt", "var/lib/dpkg/status"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				p := filepath.Join(dir, filepath.FromSlash(f))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte(path.Base(f)), 0o644))
			}
			for name, target := range tt.links {
				require.NoError(t, os.Symlink(target, filepath.Join(dir, name)))
			}

			var got []string
			err := NewFSWalker(filepath.Join(dir, tt.root)).Walk(t.Context(), filepath.Join(dir, tt.root), tt.option, func(_ context.Context, filePath string, _ os.FileInfo, opener analyzer.Opener) error {
				got = append(got, filePath)
				f, err := opener()
				require.NoError(t, err)
				defer f.Close()
				b, err := io.ReadAll(f)
				require.NoError(t, err)
				assert.Equal(t, path.Base(filePath), string(b))
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestFS_WalkDeepTree walks a tree whose deepest paths pass PATH_MAX, where
// a listing by path stops. The walk passes over them and reports the rest.
func TestFS_WalkDeepTree(t *testing.T) {
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer r.Close()
	long := strings.Repeat(strings.Repeat("d", 200)+"/", 19)
	deep := long + strings.Repeat(strings.Repeat("d", 200)+"/", 3)
	require.NoError(t, r.MkdirAll(deep, 0o755))
	require.NoError(t, r.WriteFile(deep+"deep.txt", []byte("deep.txt"), 0o644))
	require.NoError(t, r.WriteFile(long+strings.Repeat("f", 250), []byte("f"), 0o644))
	require.NoError(t, r.WriteFile("top.txt", []byte("top.txt"), 0o644))

	var got []string
	err = NewFSWalker(dir).Walk(t.Context(), dir, walker.Option{}, func(_ context.Context, filePath string, _ os.FileInfo, _ analyzer.Opener) error {
		got = append(got, filePath)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"top.txt"}, got)
}

// TestFS_WalkStaticPaths walks a static path inside a scan root, next to an
// outside directory that a link may point at.
func TestFS_WalkStaticPaths(t *testing.T) {
	const abs = "abs:" // a link target that names a path in the test directory
	tests := []struct {
		name     string
		files    []string          // relative to the test directory
		links    map[string]string // name to target
		scanRoot string            // relative to the test directory
		slash    bool              // scan / instead, with static under the scan root
		static   string            // relative to the scan root
		want     []string          // path=contents of each file visited
	}{
		{
			name:   "in-root link to a file",
			files:  []string{"root/usr/lib/os-release"},
			links:  map[string]string{"root/etc/os-release": "../usr/lib/os-release"},
			static: "etc/os-release",
			want:   []string{".=os-release"},
		},
		{
			name:   "absolute link",
			files:  []string{"outside/os-release"},
			links:  map[string]string{"root/etc/os-release": abs + "outside/os-release"},
			static: "etc/os-release",
		},
		{
			name:   "link that climbs out",
			files:  []string{"outside/os-release"},
			links:  map[string]string{"root/etc/os-release": "../../outside/os-release"},
			static: "etc/os-release",
		},
		{
			name:   "loop",
			links:  map[string]string{"root/etc/os-release": "os-release"},
			static: "etc/os-release",
		},
		{
			name:   "file in the path",
			files:  []string{"root/etc"},
			static: "etc/os-release",
		},
		{
			name:   "more steps than os.Root takes",
			files:  []string{"root/etc/x/f", "root/usr/lib/os-release"},
			links:  map[string]string{"root/etc/os-release": strings.Repeat("x/../", 86) + "../usr/lib/os-release"},
			static: "etc/os-release",
		},
		{
			name:   "missing",
			files:  []string{"root/usr/lib/os-release"},
			static: "etc/os-release",
		},
		{
			name:   "in-root link to a directory",
			files:  []string{"root/usr/lib/sysimage/rpm/rpmdb.sqlite"},
			links:  map[string]string{"root/var/lib/rpm": "../../usr/lib/sysimage/rpm"},
			static: "var/lib/rpm",
			want:   []string{"rpmdb.sqlite=rpmdb.sqlite"},
		},
		{
			name:   "absolute link to a directory",
			files:  []string{"outside/rpm/rpmdb.sqlite"},
			links:  map[string]string{"root/var/lib/rpm": abs + "outside/rpm"},
			static: "var/lib/rpm",
		},
		{
			name:     "root is a link",
			files:    []string{"root/etc/os-release"},
			links:    map[string]string{"rootlink": "root"},
			scanRoot: "rootlink",
			static:   "etc/os-release",
			want:     []string{".=os-release"},
		},
		{
			name:   "absolute link under /",
			files:  []string{"outside/os-release"},
			links:  map[string]string{"root/etc/os-release": abs + "outside/os-release"},
			slash:  true,
			static: "etc/os-release",
			want:   []string{".=os-release"},
		},
		{
			name:   "absolute link to a directory under /",
			files:  []string{"outside/rpm/rpmdb.sqlite"},
			links:  map[string]string{"root/var/lib/rpm": abs + "outside/rpm"},
			slash:  true,
			static: "var/lib/rpm",
			want:   []string{"rpmdb.sqlite=rpmdb.sqlite"},
		},
		{
			name:   "loop under /",
			links:  map[string]string{"root/etc/os-release": "os-release"},
			slash:  true,
			static: "etc/os-release",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "root"), 0o755))
			for _, f := range tt.files {
				p := filepath.Join(dir, filepath.FromSlash(f))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte(path.Base(f)), 0o644))
			}
			for name, target := range tt.links {
				if p, ok := strings.CutPrefix(target, abs); ok {
					target = filepath.Join(dir, filepath.FromSlash(p))
				}
				p := filepath.Join(dir, filepath.FromSlash(name))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.Symlink(target, p))
			}
			scanRoot := tt.scanRoot
			if scanRoot == "" {
				scanRoot = "root"
			}
			root := filepath.Join(dir, scanRoot)
			name := filepath.Join(root, filepath.FromSlash(tt.static))
			if tt.slash {
				root = "/"
			}

			var got []string
			err := NewFSWalker(root).Walk(t.Context(), name, walker.Option{}, func(_ context.Context, filePath string, _ os.FileInfo, opener analyzer.Opener) error {
				f, err := opener()
				require.NoError(t, err)
				defer f.Close()
				b, err := io.ReadAll(f)
				require.NoError(t, err)
				got = append(got, filePath+"="+string(b))
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
