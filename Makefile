LICENSE-3rdparty.csv: go.mod go.sum
	# this requires a GITHUB_TOKEN env var that can access this repo
	dd-license-attribution https://github.com/DataDog/ddtrivy > $@
