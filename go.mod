module github.com/DataDog/ddtrivy

go 1.26.6

replace github.com/aquasecurity/trivy => github.com/DataDog/trivy v0.76.3-0.20261109094403-eae976d6dbfc

require (
	github.com/aquasecurity/trivy v0.69.1
	github.com/aquasecurity/trivy-db v0.0.0-20261012084708-cbebf2ecd6df
	github.com/aquasecurity/trivy-java-db v0.0.0-20250520062418-66df85428c9e
	github.com/google/go-containerregistry v0.22.1
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.12.1
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da
)

require (
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/DataDog/zstd v1.5.5 // indirect
	github.com/ProtonMail/go-crypto v1.5.2 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/aquasecurity/go-gem-version v0.0.0-20201115065557-8eed6fe000ce // indirect
	github.com/aquasecurity/go-npm-version v0.0.3-0.20261005070944-1f16ed76cf11 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.2-0.20260224065243-f9bba28c51a4 // indirect
	github.com/aquasecurity/go-version v0.0.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.47.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.33.9 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/aws/smithy-go v1.28.5 // indirect
	github.com/bitnami/go-version v0.0.0-20231130084017-bb00604d650c // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.3 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/cenkalti/backoff/v6 v6.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cheggaaa/pb/v3 v3.2.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/containerd/continuity v0.5.0 // indirect
	github.com/docker/cli v29.8.2+incompatible // indirect
	github.com/docker/docker v28.5.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.9 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-openapi/jsonpointer v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/google/wire v0.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/josephburnett/jd/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f // indirect
	github.com/knqyf263/go-deb-version v0.0.0-20241115132648-6f4aee6ccd23 // indirect
	github.com/knqyf263/go-rpm-version v0.0.0-20260811110310-1815e1f1b790 // indirect
	github.com/knqyf263/go-rpmdb v0.1.2-0.20241125135340-7670f0f23c16 // indirect
	github.com/knqyf263/nested v0.0.1 // indirect
	github.com/lunixbochs/struc v0.0.0-20200707160740-784aaebc1d40 // indirect
	github.com/masahiro331/go-disk v0.0.0-20260423015231-f7a470ebd472 // indirect
	github.com/masahiro331/go-ext4-filesystem v0.0.0-20260423010602-fe51f5b5e52b // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20260119054159-d21fcd2e7de1 // indirect
	github.com/masahiro331/go-xfs-filesystem v0.0.0-20260422061116-d21e5e4481bb // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/mattn/go-shellwords v1.0.16 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/package-url/packageurl-go v0.1.7 // indirect
	github.com/pandatix/go-cvss v0.6.2 // indirect
	github.com/redis/go-redis/v9 v9.23.0 // indirect
	github.com/rust-secure-code/go-rustaudit v0.0.0-20250226111315-e20ec32e963c // indirect
	github.com/samber/oops v1.18.1 // indirect
	github.com/sassoftware/go-rpmutils v0.4.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/twitchtv/twirp v8.1.3+incompatible // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.2 // indirect
	k8s.io/utils v0.0.0-20260626114624-be93311217bd // indirect
)
