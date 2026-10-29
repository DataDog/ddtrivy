// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package ddtrivy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fswalker "github.com/DataDog/ddtrivy/walker"
)

func TestDisablesAnalyzersIsComplete(t *testing.T) {
	analyzers := getTrivyDisabledAnalyzers(nil)
	set := make(map[analyzer.Type]struct{})
	for _, a := range analyzers {
		//exhaustive:enforce
		switch a {
		case analyzer.TypeOSRelease,
			analyzer.TypeAlpine,
			analyzer.TypeAmazon,
			analyzer.TypeAzure,
			analyzer.TypeCBLMariner,
			analyzer.TypeDebian,
			analyzer.TypePhoton,
			analyzer.TypeCentOS,
			analyzer.TypeRocky,
			analyzer.TypeAlma,
			analyzer.TypeFedora,
			analyzer.TypeOracle,
			analyzer.TypeRedHatBase,
			analyzer.TypeSUSE,
			analyzer.TypeUbuntu,
			analyzer.TypeUbuntuESM,
			analyzer.TypeCoreOS,
			analyzer.TypeApk,
			analyzer.TypeBottlerocketInventory,
			analyzer.TypeDpkg,
			analyzer.TypeDpkgLicense,
			analyzer.TypeRpm,
			analyzer.TypeRpmArchive,
			analyzer.TypeRpmqa,
			analyzer.TypeApkRepo,
			analyzer.TypeBundler,
			analyzer.TypeGemSpec,
			analyzer.TypeCargo,
			analyzer.TypeComposer,
			analyzer.TypeJar,
			analyzer.TypePom,
			analyzer.TypeGradleLock,
			analyzer.TypeSbtLock,
			analyzer.TypeNpmPkgLock,
			analyzer.TypeNodePkg,
			analyzer.TypeYarn,
			analyzer.TypePnpm,
			analyzer.TypeBun,
			analyzer.TypeNuget,
			analyzer.TypeDotNetCore,
			analyzer.TypePackagesProps,
			analyzer.TypeCondaPkg,
			analyzer.TypeCondaEnv,
			analyzer.TypePythonPkg,
			analyzer.TypePythonPkgEgg,
			analyzer.TypePip,
			analyzer.TypePipenv,
			analyzer.TypePoetry,
			analyzer.TypeUv,
			analyzer.TypeGoBinary,
			analyzer.TypeGoMod,
			analyzer.TypeRustBinary,
			analyzer.TypeConanLock,
			analyzer.TypeCocoaPods,
			analyzer.TypeSwift,
			analyzer.TypePubSpecLock,
			analyzer.TypeMixLock,
			analyzer.TypeJulia,
			analyzer.TypeComposerVendor,
			analyzer.TypeAzureARM,
			analyzer.TypeCloudFormation,
			analyzer.TypeDockerfile,
			analyzer.TypeHelm,
			analyzer.TypeKubernetes,
			analyzer.TypeTerraform,
			analyzer.TypeTerraformPlanJSON,
			analyzer.TypeTerraformPlanSnapshot,
			analyzer.TypeYAML,
			analyzer.TypeJSON,
			analyzer.TypeAnsible,
			analyzer.TypeExecutable,
			analyzer.TypeSBOM,
			analyzer.TypeApkCommand,
			analyzer.TypeHistoryDockerfile,
			analyzer.TypeImageConfigSecret,
			analyzer.TypeLicenseFile,
			analyzer.TypeSecret,
			analyzer.TypeRedHatContentManifestType,
			analyzer.TypeRedHatDockerfileType:
			set[a] = struct{}{}
		default:
			t.Fatalf("unexpected analyzer %s", a)
		}
	}
	if len(set) != 79 {
		t.Fatalf("missing analyzer: expected 79 got %d", len(set))
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
