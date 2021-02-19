.DEFAULT_GOAL:=help
TMPDIR ?= /tmp

##@ Testing

test: docker_compose_up cargo_test clean## Launch docker compose and run tests

#TODO: check for docker and docker compose
docker_compose_up:
	docker-compose -f ./tools/docker-compose.yml up --detach

cargo_test: 
	cargo test -- --nocapture

clean: ## Clean up temporary test resources
	rm -r ${TMPDIR}/washtest
	docker-compose -f ./tools/docker-compose.yml down

##@ Helpers

help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_\-.*]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)