// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package ddtrivy

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	if len(set) != 76 {
		t.Fatalf("missing analyzer: expected 76 got %d", len(set))
	}
}

func TestFastOSScan(t *testing.T) {
	options := TrivyOptionsOS(1)
	assert.Equal(t, options.WalkerOption.OnlyDirs, osPkgDirs)
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

func TestTrivyOptionsAppsDisablesOSAnalyzers(t *testing.T) {
	opt := trivyOptionsApps(1)
	disabled := make(map[analyzer.Type]struct{}, len(opt.DisabledAnalyzers))
	for _, a := range opt.DisabledAnalyzers {
		disabled[a] = struct{}{}
	}
	// The apps phase must run with OS analyzers off (so ScanHostFS's skip set
	// can drop package files) and the executable analyzer on (the costly one
	// the skip set spares from re-scanning every binary), over the whole tree.
	for _, a := range getOSAnalyzers() {
		assert.Containsf(t, disabled, a, "OS analyzer %q must be disabled", a)
	}
	assert.NotContains(t, disabled, analyzer.TypeExecutable, "executable analyzer must stay enabled")
	assert.Empty(t, opt.WalkerOption.OnlyDirs, "apps phase must walk the whole tree")
}

func TestCollectInstalledFiles(t *testing.T) {
	report := &trivytypes.Report{
		Results: trivytypes.Results{
			{
				Packages: []ftypes.Package{
					{Name: "glibc", InstalledFiles: []string{"/usr/lib64/libc.so.6", "/usr/bin/ldd"}},
					{Name: "rel", InstalledFiles: []string{"var/lib/already-relative"}},
					{Name: "thirdparty"}, // no InstalledFiles -> contributes nothing
				},
			},
		},
	}
	assert.Equal(t, map[string]struct{}{
		"usr/lib64/libc.so.6":      {},
		"usr/bin/ldd":              {},
		"var/lib/already-relative": {},
	}, collectInstalledFiles(report))
}

func TestMergeReports(t *testing.T) {
	osPtr := &ftypes.OS{}
	osReport := &trivytypes.Report{
		Metadata: trivytypes.Metadata{OS: osPtr},
		Results:  trivytypes.Results{{Target: "os", Class: trivytypes.ClassOSPkg}},
	}
	appsReport := &trivytypes.Report{
		Results: trivytypes.Results{{Target: "apps", Class: trivytypes.ClassLangPkg}},
	}

	merged := mergeReports(osReport, appsReport)
	require.Len(t, merged.Results, 2)
	assert.Equal(t, trivytypes.ClassOSPkg, merged.Results[0].Class)
	assert.Equal(t, trivytypes.ClassLangPkg, merged.Results[1].Class)
	assert.Same(t, osPtr, merged.Metadata.OS, "phase-1 OS metadata must be preserved")
}
