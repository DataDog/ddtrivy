// Package scanners implements the different scanners that can be launched by
// our agentless scanner.
package scanners

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-agentless-scanner/pkg/log"
	"github.com/DataDog/datadog-agentless-scanner/pkg/types"
	ddogstatsd "github.com/DataDog/datadog-go/v5/statsd"
	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy-db/pkg/db"
	jdb "github.com/aquasecurity/trivy-java-db/pkg/db"
	trivycache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	trivyartifactcontainer "github.com/aquasecurity/trivy/pkg/fanal/artifact/container"
	trivyartifactlocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/container"
	trivyhandler "github.com/aquasecurity/trivy/pkg/fanal/handler"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	trivyscanner "github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

var (
	trivyCacheDir      = types.CacheRootDir("trivy")
	trivyJavaDBDirname = filepath.Join(trivyCacheDir, "java-db")
)

var trivyDefaultJavaDBRepositories = []string{
	fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-java-db", jdb.SchemaVersion),
	fmt.Sprintf("%s:%d", "public.ecr.aws/aquasecurity/trivy-java-db", jdb.SchemaVersion),
}

var trivyInitOnce sync.Once

var trivyDefaultSkipDirs = []string{
	// already included in Trivy's defaultSkipDirs
	// "**/.git",
	// "proc",
	// "sys",
	// "dev",

	"**/.cargo/git/**",
}

var osPkgDirs = []string{
	"etc/*",
	"usr/lib/*",
	"var/lib/dpkg/*",
	"var/lib/rpm/*",
	"usr/lib/sysimage/rpm/*",
	"lib/apk/db/*",
	"aarch64-bottlerocket-linux-gnu/sys-root/usr/lib/*",
	"aarch64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/*",
	"x86_64-bottlerocket-linux-gnu/sys-root/usr/lib/*",
	"x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/*",
}

func initTrivyJavaDB() {
	var repos []name.Reference
	for _, url := range trivyDefaultJavaDBRepositories {
		repo, err := name.NewTag(url)
		if err != nil {
			panic(fmt.Errorf("failed to initialize JavaDB: %w", err))
		}
		repos = append(repos, repo)
	}
	javadb.Init(trivyCacheDir, repos, false, false, ftypes.RegistryOptions{})
}

// Initialize and download the JavaDB required for Trivy application scans.
func InitTrivy(ctx context.Context) error {
	if err := os.MkdirAll(trivyJavaDBDirname, 0755); err != nil {
		return fmt.Errorf("failed to create JavaDB directory: %w", err)
	}

	initTrivyJavaDB()

	// Let's not trust Trivy on this one, since this is called in our critical
	// startup path. We add a timeout to the update process.
	errch := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errch <- fmt.Errorf("javadb update failed: %v", r)
			}
		}()
		if err := javadb.Update(); err != nil {
			errch <- fmt.Errorf("javadb update failed: %w", err)
		} else {
			log.Infof("javadb updated")
			errch <- nil
		}
	}()

	select {
	case err := <-errch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

var trivyAnalyzersAll = []analyzer.Type{
	// TypeOSes
	analyzer.TypeOSRelease,
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
	// TypeOSes
	analyzer.TypeSUSE,
	analyzer.TypeUbuntu,
	analyzer.TypeUbuntuESM,
	analyzer.TypeApk,
	analyzer.TypeBottlerocket,
	analyzer.TypeDpkg,
	analyzer.TypeDpkgLicense,
	analyzer.TypeRpm,
	analyzer.TypeRpmArchive,
	analyzer.TypeRpmqa,
	analyzer.TypeApkRepo,
	// TypeLanguages
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
	// TypeIndividualPkgs
	analyzer.TypeComposerVendor,
	// TypeConfigFiles
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
	// Non-packaged
	analyzer.TypeExecutable,
	analyzer.TypeSBOM,
	// Image Config
	analyzer.TypeApkCommand,
	analyzer.TypeHistoryDockerfile,
	analyzer.TypeImageConfigSecret,
	// License
	analyzer.TypeLicenseFile,
	// Secrets
	analyzer.TypeSecret,
	// Red Hat
	analyzer.TypeRedHatContentManifestType,
	analyzer.TypeRedHatDockerfileType,
}

func getTrivyDisabledAnalyzers(allowedAnalyzers []analyzer.Type) []analyzer.Type {
	var disabledAnalyzers []analyzer.Type

	for _, a := range trivyAnalyzersAll {
		if !slices.Contains(allowedAnalyzers, a) {
			disabledAnalyzers = append(disabledAnalyzers, a)
		}
	}

	unique := make(map[analyzer.Type]struct{})
	for _, a := range disabledAnalyzers {
		unique[a] = struct{}{}
	}

	disabledAnalyzers = disabledAnalyzers[:0]
	for a := range unique {
		disabledAnalyzers = append(disabledAnalyzers, a)
	}

	return disabledAnalyzers
}

func excludeTrivyAnalyzer(allowedAnalyzers []analyzer.Type, filtered analyzer.Type) []analyzer.Type {
	analyzers := make([]analyzer.Type, 0, len(allowedAnalyzers))
	for _, a := range allowedAnalyzers {
		if a != filtered {
			analyzers = append(analyzers, a)
		}
	}
	return analyzers
}

func trivyOptionsOS() artifact.Option {
	var allowedAnalyzers []analyzer.Type
	allowedAnalyzers = append(allowedAnalyzers, excludeTrivyAnalyzer(analyzer.TypeOSes, analyzer.TypeDpkgLicense)...)
	return artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: getTrivyDisabledAnalyzers(allowedAnalyzers),
		Parallel:          1,
		SBOMSources:       []string{},
		DisabledHandlers:  []ftypes.HandlerType{ftypes.UnpackagedPostHandler},
		WalkerOption: walker.Option{
			SkipDirs: trivyDefaultSkipDirs,
			OnlyDirs: osPkgDirs,
		},
	}
}

// trivyOptionsAllForHosts returns the default options for trivy to scan applications
// on possibly big hosts root filesystems.
func trivyOptionsAllForHosts() artifact.Option {
	var allowedAnalyzers []analyzer.Type
	allowedAnalyzers = append(allowedAnalyzers, excludeTrivyAnalyzer(analyzer.TypeOSes, analyzer.TypeDpkgLicense)...)
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeIndividualPkgs...)
	// Enables the executable analyzer to retrieve version for java, nodejs, php and python interpreters.
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeExecutable)
	return artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: getTrivyDisabledAnalyzers(allowedAnalyzers),
		Parallel:          1,
		SBOMSources:       []string{},
		DisabledHandlers:  []ftypes.HandlerType{ftypes.UnpackagedPostHandler},
		WalkerOption: walker.Option{
			SkipDirs: trivyDefaultSkipDirs,
			OnlyDirs: append(osPkgDirs, []string{
				"opt/**",
				"usr/local/**",
			}...),
		},
	}
}

// trivyOptionsAll returns the default options for trivy to scan application and
// OS packages.
func trivyOptionsAll() artifact.Option {
	var allowedAnalyzers []analyzer.Type
	// Enable the OS packages analyzers to fill the SystemInstalledFiles list with the list of files
	// installed by the package managers, so they are excluded from the other analyzers.
	// This requires access to the /lib/apk/db, /usr/lib/sysimage/rpm and /var/lib/dpkg directories.
	//
	// We remove specifically analyzer.TypeDpkgLicense included in TypeOSes from the list of
	// allowed analyzers to avoid license scanning.
	allowedAnalyzers = append(allowedAnalyzers, excludeTrivyAnalyzer(analyzer.TypeOSes, analyzer.TypeDpkgLicense)...)
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeLanguages...)
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeLockfiles...)
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeIndividualPkgs...)
	// Enables the executable analyzer to retrieve version for java, nodejs, php and python interpreters.
	allowedAnalyzers = append(allowedAnalyzers, analyzer.TypeExecutable)

	return artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: getTrivyDisabledAnalyzers(allowedAnalyzers),
		Parallel:          2,
		SBOMSources:       []string{},
		DisabledHandlers:  []ftypes.HandlerType{ftypes.UnpackagedPostHandler},
		WalkerOption: walker.Option{
			SkipDirs: append([]string{
				"bin/**",
				"boot/**",
				"dev/**",
				"media/**",
				"mnt/**",
				"proc/**",
				"run/**",
				"sbin/**",
				"sys/**",
				"tmp/**",
				"usr/bin/**",
				"usr/sbin/**",
				"var/cache/**",
				"var/lib/containerd/**",
				"var/lib/containers/**",
				"var/lib/docker/**",
				"var/lib/libvirt/**",
				"var/lib/snapd/**",
				"var/log/**",
				"var/run/**",
				"var/tmp/**",
			}, trivyDefaultSkipDirs...),
		},
	}
}

func trivyOptions(opts types.ScannerOptions) artifact.Option {
	switch opts.Action {
	case types.ScanActionVulnsHostOS,
		types.ScanActionVulnsRunningContainersOS,
		types.ScanActionVulnsContainerImagesOS:
		return trivyOptionsOS()
	case types.ScanActionVulnsHostApp:
		return trivyOptionsAllForHosts()
	case types.ScanActionVulnsApp,
		types.ScanActionVulnsRunningContainersApp,
		types.ScanActionVulnsContainerImagesApp:
		return trivyOptionsAll()
	}
	panic(fmt.Sprintf("unsupported action for trivy: %s", opts.Action))
}

// LaunchTrivyRootFS launches a trivy scan on a root filesystems.
func LaunchTrivyRootFS(ctx context.Context, sc *types.ScannerConfig, statsd ddogstatsd.ClientInterface, opts types.ScannerOptions, artifactOpts artifact.Option) (*types.ScanResultVulns, error) {
	// NOTE: the trivy cache key calculated based on the artifact options will
	// always be different because of this.
	wo := &artifactOpts.WalkerOption
	wo.OnlyDirs = rootFiles(opts.Entity.RootFS(), wo.OnlyDirs)
	wo.SkipDirs = rootFiles(opts.Entity.RootFS(), wo.SkipDirs)
	wo.SkipFiles = rootFiles(opts.Entity.RootFS(), wo.SkipFiles)
	fs := walker.NewFS()
	trivyCache := trivycache.NewMemoryCache()
	trivyArtifact, err := trivyartifactlocal.NewArtifact(opts.Entity.RootFS(), trivyCache, fs, artifactOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create local trivy artifact: %w", err)
	}
	return doTrivyScan(ctx, opts, trivyArtifact, trivyCache)
}

// LaunchTrivyOverlays launches a trivy scan on a local filesystem represened by
// a set of overlays.
func LaunchTrivyOverlays(ctx context.Context, sc *types.ScannerConfig, statsd ddogstatsd.ClientInterface, opts types.ScannerOptions, artifactOpts artifact.Option) (*types.ScanResultVulns, error) {
	fs := walker.NewFS()
	var trivyCache interface {
		trivycache.LocalArtifactCache
		trivycache.ArtifactCache
	}
	if sc.ScanCacheDisabled {
		trivyCache = trivycache.NewMemoryCache()
	} else {
		trivyCache = loadTrivyFSCache(statsd)
	}
	ctr := container.NewContainer(
		opts.Entity.ContainerImage.RefCanonical(),
		opts.Entity.ContainerImage.RefTagged(),
		opts.Entity.ContainerImage.ImageID,
		opts.Entity.ContainerImage.ConfigFile,
		toLayerPath(opts.Entity.Overlays()))
	trivyArtifact, err := trivyartifactcontainer.NewArtifact(ctr, trivyCache, fs, artifactOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from fs: %w", err)
	}
	return doTrivyScan(ctx, opts, trivyArtifact, trivyCache)
}

func doTrivyScan(ctx context.Context, opts types.ScannerOptions, trivyArtifact artifact.Artifact, trivyCache trivycache.LocalArtifactCache) (*types.ScanResultVulns, error) {
	trivyInitOnce.Do(func() {
		// Making sure the Unpackaged post handler relying on external DBs is
		// deregistered
		trivyhandler.DeregisterPostHandler(ftypes.UnpackagedPostHandler)

		// Init the JavaDB required for trivy application scans
		initTrivyJavaDB()
	})

	trivyOSScanner := ospkg.NewScanner()
	trivyLangScanner := langpkg.NewScanner()
	trivyVulnClient := vulnerability.NewClient(db.Config{})
	trivyApplier := applier.NewApplier(trivyCache)
	trivyLocalScanner := local.NewScanner(trivyApplier, trivyOSScanner, trivyLangScanner, trivyVulnClient)
	trivyScanner := trivyscanner.NewScanner(trivyLocalScanner, trivyArtifact)

	log.Debugf("%s: trivy: starting scan", opts.Scan)
	trivyReport, err := trivyScanner.ScanArtifact(ctx, trivytypes.ScanOptions{
		Scanners:            trivytypes.Scanners{trivytypes.SBOMScanner},
		ScanRemovedPackages: false,
		PkgTypes:            trivytypes.PkgTypes,
		PkgRelationships:    ftypes.Relationships,
	})
	if err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}
	log.Debugf("%s: trivy: scan of artifact finished successfully", opts.Scan)
	marshaler := cyclonedx.NewMarshaler("")
	cyclonedxBOM, err := marshaler.MarshalReport(ctx, trivyReport)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal report to sbom format: %w", err)
	}
	if img := opts.Entity.ContainerImage; img != nil {
		appendSBOMRepoMetadata(cyclonedxBOM, img.ContainerReferences)
	}
	return &types.ScanResultVulns{
		BOM: cyclonedxBOM,
	}, nil
}

func rootFiles(root string, files []string) []string {
	s := make([]string, 0, len(files))
	for _, file := range files {
		s = append(s, filepath.Join(root, file))
	}
	return s
}

func toLayerPath(layers []types.ContainerImageLayer) []ftypes.LayerPath {
	new := make([]ftypes.LayerPath, 0, len(layers))
	for _, layer := range layers {
		new = append(new, ftypes.LayerPath{
			DiffID: layer.DiffID,
			Digest: layer.Digest,
			Path:   layer.Path,
		})
	}
	return new
}

// hasLinuxPackageFiles returns true when the target root file system contains
// a directory supported by Trivy's operating system packages analyzers.
func hasLinuxPackageFiles(opts types.ScannerOptions) (string, bool) {
	for _, dir := range osPkgDirs {
		name := strings.TrimRight(dir, "*") // Remove wildcards
		_, err := os.Stat(path.Join(opts.Entity.RootFS(), name))
		if err != nil {
			continue
		}
		return name, true
	}
	return "", false
}
