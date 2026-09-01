SHELL := /bin/bash

.PHONY: help vendorize build-offline check lint test ci-build

help:
	@echo "Available make targets:"
	@echo "  vendorize       - run tools/offline/vendorize.sh to create vendor/"
	@echo "  build-offline   - run tools/offline/build-offline.sh on air-gapped host"
	@echo "  check           - run version, lint, compile, migration, and test gates"
	@echo "  lint            - run the repository Ruff gate"
	@echo "  test            - run the complete pytest suite"

vendorize:
	./tools/offline/vendorize.sh

build-offline:
	./tools/offline/build-offline.sh

check: lint test
	python3 tools/release_version.py --check
	python3 -m compileall -q app.py installer serviceops_core tools
	test "$$(alembic heads | wc -l | tr -d ' ')" = "1"

lint:
	ruff check .

test:
	pytest -q

ci-build:
	# Build locally for CI testing; never push from this target.
	docker build -t serviceops:local -f Dockerfile .
