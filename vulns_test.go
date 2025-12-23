// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

package ddtrivy

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/stretchr/testify/assert"
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
