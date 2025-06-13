LICENSE-3rdparty.csv:
	# this requires a GITHUB_TOKEN env var that can access this repo
	dd-license-attribution https://github.com/DataDog/ddtrivy > $@
