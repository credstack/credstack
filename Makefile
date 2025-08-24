GC = go
GFLAGS = '-ldflags="-s -w"'
DEV_GFLAGS = -v -x
BUILD_FOLDER=dist/
LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))

# config - Creates a config file with sane defaults
config:
	mkdir -p ~/.credstack/logs
	cp $(pwd)/configs/server.config ~/.credstack/config.json

# api - Builds the api and outputs it to the BUILD_FOLDER
api:
	$(GC) build cmd/api $(GFLAGS) -o dist/credstack-api

# docker - Builds a docker image and tags it with the latest accessible git tag
docker:
	docker build . -t credstack-api:$(LATEST_TAG)

# clean - Removes build artifacts
.PHONY: clean
clean:
	rm -rf dist/
	rm -rf build/
