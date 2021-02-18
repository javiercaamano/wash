.DEFAULT_GOAL:=help
# CAPABILITY_ID := $(call readvar,CAPABILITY_ID)
# NAME          := $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name')
# DESTINATION   ?= fs.par.gz

##@ Testing

test: ## Launch docker compose and run tests
	docker-compose -f ./tools/docker-compose.yml up --detach
	cargo test -- --nocapture
	docker-compose -f ./tools/docker-compose.yml down

##@ Helpers

clean: ## Clean up temporary test directories 
	rm -rf ./_reg_test

help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_\-.*]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)