// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package ddtrivy

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	trivycache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fswalker "github.com/DataDog/ddtrivy/walker"
)

// getTrivyDisabledAnalyzers returns trivyAnalyzersAll minus the allowed
// analyzers, so an analyzer that Trivy registers outside that list runs in
// every scan.
func TestDisablesAnalyzersIsComplete(t *testing.T) {
	ag, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	versions := ag.AnalyzerVersions()
	require.NotEmpty(t, versions.Analyzers, "Trivy registers no analyzers")
	disabled := getTrivyDisabledAnalyzers(nil)
	for _, registered := range []map[string]int{versions.Analyzers, versions.PostAnalyzers} {
		for _, name := range slices.Sorted(maps.Keys(registered)) {
			// TestScanRootFSPartialReport registers deadline for itself.
			if analyzer.Type(name) == (deadlineAnalyzer{}).Type() {
				continue
			}
			assert.Contains(t, disabled, analyzer.Type(name), "getTrivyDisabledAnalyzers(nil) is missing %s, which Trivy registers", name)
		}
	}
}

func TestFastOSScan(t *testing.T) {
	options := TrivyOptionsOS(1)
	assert.Nil(t, options.WalkerOption.OnlyDirs)
}

func TestLooselyCompareAnalyzers(t *testing.T) {
	entries := []struct {
		name     string
		given    []analyzer.Type
		against  []analyzer.Type
		expected bool
	}{
		{
			name:     "empty lists",
			expected: true,
		},
		{
			name:     "os simple",
			given:    []analyzer.Type{"os"},
			against:  []analyzer.Type{"os"},
			expected: true,
		},
		{
			name:     "os duplicated",
			given:    []analyzer.Type{"os", "os"},
			against:  []analyzer.Type{"os"},
			expected: true,
		},
		{
			name:     "os wrong",
			given:    []analyzer.Type{"languages"},
			against:  []analyzer.Type{"os"},
			expected: false,
		},
		{
			name:     "languages and os",
			given:    []analyzer.Type{"os", "languages"},
			against:  []analyzer.Type{"os", "languages"},
			expected: true,
		},
		{
			name:     "languages and os 2",
			given:    []analyzer.Type{"languages", "os"},
			against:  []analyzer.Type{"os", "languages"},
			expected: true,
		},
	}

	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			assert.Equal(t, entry.expected, looselyCompareAnalyzers(entry.given, entry.against))
		})
	}
}

// The kubelet stages raw block volumes under volumeDevices, as device
// nodes or as files a device is bind mounted on, which go away when the
// volume detaches.
func TestTrivyOptionsAllSkipsVolumeDevices(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"opt/app/package.json",
		"var/lib/kubelet/plugins/kubernetes.io/csi/volumeDevices/pvc-1/dev/7ab689dc",
	} {
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0o755))
	}

	wo := TrivyOptionsAll(1).WalkerOption
	wo.OnlyDirs = rootFiles(root, wo.OnlyDirs)
	wo.SkipDirs = rootFiles(root, wo.SkipDirs)
	wo.SkipFiles = rootFiles(root, wo.SkipFiles)
	var got []string
	err := fswalker.NewFSWalker().Walk(context.Background(), root, wo, func(_ context.Context, p string, _ os.FileInfo, _ analyzer.Opener) error {
		got = append(got, p)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"opt/app/package.json"}, got)
}

// deadlineAnalyzer fails as a post analyzer does when its
// PostAnalyzerTimeout ends it.
type deadlineAnalyzer struct{}

func (deadlineAnalyzer) Type() analyzer.Type                      { return "deadline" }
func (deadlineAnalyzer) Version() int                             { return 1 }
func (deadlineAnalyzer) Required(path string, _ os.FileInfo) bool { return path == "deadline" }

func (deadlineAnalyzer) PostAnalyze(context.Context, analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	return nil, context.DeadlineExceeded
}

func init() {
	analyzer.RegisterPostAnalyzer("deadline", func(analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
		return deadlineAnalyzer{}, nil
	})
}

// A scan that runs out of time after its walk keeps the packages it found.
func TestScanRootFSPartialReport(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"etc/alpine-release":   "3.20.3\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:x86_64\n\n",
		"deadline":             "\n",
	} {
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}

	report, err := ScanRootFS(context.Background(), TrivyOptionsAll(1), trivycache.NewMemoryCache(), root, ftypes.TypeFilesystem)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotNil(t, report)
	var pkgs []string
	for _, r := range report.Results {
		for _, p := range r.Packages {
			pkgs = append(pkgs, p.Name+"@"+p.Version)
		}
	}
	assert.Equal(t, []string{"musl@1.2.5-r0"}, pkgs)
}
