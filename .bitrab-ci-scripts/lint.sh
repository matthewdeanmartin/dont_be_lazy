#!/usr/bin/env bash
set -euo pipefail
source ./.bitrab-ci-scripts/setup.sh
uv run isort --check-only dont_be_lazy tests
uv run black --check dont_be_lazy tests
uv run ruff check --quiet dont_be_lazy tests
uv run pylint --score=n --reports=n --rcfile=.pylintrc dont_be_lazy
uv run pylint --score=n --reports=n --rcfile=.pylintrc_tests tests
