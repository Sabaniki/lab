SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

P4_PROG_NAME := main


##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: ins-homa
ins-homa: ## install homa kernelmodule
	cd Homa/HomaModule && sudo insmod ./homa.ko

.PHONY: rm-homa
rm-homa: ## remove homa kernelmodule
	sudo rmmod homa

##@ Build

.PHONY: p4-build
p4-build: ## Build P4 source code.
	docker run --rm -v $(CURDIR)/P4:/p4c p4lang/p4c p4c --target bmv2 --arch v1model $(P4_PROG_NAME).p4 --p4runtime-files p4info.txt

.PHONY: p4-image
p4-image: ## Build custom Docker image named "sabaniki/bmv2:latest".
	cd bmv2 && docker build -t sabaniki/bmv2 .

.PHONY: homa-image
homa-image: ## Build custom Docker image named "sabaniki/homa:latest".
	cd Homa && docker build -t sabaniki/homa .

.PHONY: env
env: p4-build p4-image homa-image tinet-reset  ## Create virtual network environment.

##@ Dev

.PHONY: tinet-up
tinet-up: ## Set up Virtual Env.
	cd topo && tinet upconf | sudo sh -x

.PHONY: tinet-down
tinet-down: ## Set up Virtual Env.
	cd topo && tinet down | sudo sh -x

.PHONY: tinet-reset
tinet-reset: tinet-down tinet-up ## Reset Virtual Env.

.PHONY: p4-update
# p4-update: p4-build tinet-down tinet-up ## Build P4 Src and Reset Virtual Env.
p4-update: rm-homa p4-build tinet-down tinet-up ins-homa ## Build P4 Src and Reset Virtual Env.

.PHONY: image-update
image-update: build tinet-reset ## Update image and reset virtual Env.

##@ Run

.PHONY: run
run: ## run P4 switch (exec this before `make set-config`)
	docker exec -it P4 simple_switch src/$(P4_PROG_NAME).json -i 1@sv -i 2@cl \
	--nanolog ipc:///tmp/bm-0-log.ipc --log-console -L debug --notifications-addr ipc:///tmp/bmv2-0-notifications.ipc \
	> ./P4/log/`date +%m-%d-%H:%M:%S`-log.txt

.PHONY: set-config
set-config: ## set runtime config to P4 switch (exec this after `make run`)
	docker exec -it P4 bash -c "cat src/runtime.txt | bm_CLI"

##@ Attach

.PHONY: cli
cli: ## attach bmv2 runtime cli
	docker exec -it P4 bm_CLI

.PHONY: events
events: ## attach bmv2 nanomsg_events
	docker exec -it P4 bm_nanomsg_events

.PHONY: p4-ns
p4-ns: ## attach p4's netns
	./nsutil/execns P4

.PHONY: server-ns
server-ns: ## attach server's netns
	./nsutil/execns Server

.PHONY: client-ns
client-ns: ## attach client's netns
	./nsutil/execns Client

.PHONY: p4-ct
p4-ct: ## attach p4's docker container
	docker exec -it P4 bash

.PHONY: server-ct
server-ct: ## attach server's docker container
	docker exec -w /homa/util -it Server bash

.PHONY: client-ct
client-ct: ## attach client's docker container
	docker exec -w /homa/util -it Client bash

##@ Measurement

.PHONY: client-ms
client-ms: ## run measurement in client
	docker exec -w /homa/util -it Client ./homa_test 192.168.0.10:4000 rtt

.PHONY: server-ms
server-ms: ## run measurement in server
	docker exec -w /homa/util -it Client ./server --verbose