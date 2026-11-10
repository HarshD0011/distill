# Local build and smoke checks for the embedded distill CLI.
#   make          unit tests, then fixture checks
#   make demo     doctor plus two sample analyses
#   make smoke    fixture checks only

CARGO ?= cargo
TARGET_DIR = $(shell $(CARGO) metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
DISTILL = $(TARGET_DIR)/debug/distill

.PHONY: help build test check smoke demo test-extension website-check website-check-links website-serve

help:
	@echo "make build   compile crates/distill-cli"
	@echo "make test    cargo test, then smoke fixtures"
	@echo "make smoke   analyze and hook fixtures against $(DISTILL)"
	@echo "make demo    doctor and sample analyze output"
	@echo "make check   cargo fmt --check and clippy"
	@echo "make website-check        validate website assets, anchors, and controls"
	@echo "make website-check-links  also verify public link destinations"
	@echo "make website-serve        preview at http://127.0.0.1:8000"

website-check:
	node --check website/app.js
	python3 website/validate.py

website-check-links:
	node --check website/app.js
	python3 website/validate.py --online

website-serve:
	python3 -m http.server 8000 --directory website --bind 127.0.0.1

build:
	$(CARGO) build -p distill-cli

test-extension: build
	cd extensions/vscode && npm run check && npm test

test: build
	$(CARGO) test --workspace
	@$(MAKE) smoke

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace -- -D warnings
	python3 scripts/validate_specs.py

demo: build
	$(DISTILL) doctor
	$(DISTILL) config validate --path config.example.toml
	$(DISTILL) analyze --cwd /tmp --command 'echo hello' --human
	$(DISTILL) analyze --cwd /tmp --command 'rm -rf /' --human

smoke: build
	python3 scripts/smoke.py $(DISTILL)
	python3 scripts/language_smoke.py $(DISTILL)
	python3 scripts/workflow_smoke.py $(DISTILL)
	python3 scripts/policy_evaluation.py $(DISTILL)
