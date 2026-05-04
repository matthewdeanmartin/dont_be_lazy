#!/usr/bin/env bash
set -euo pipefail
source ./.bitrab-ci-scripts/setup.sh
uv run interrogate dont_be_lazy --verbose --fail-under 70
uv run codespell --ignore-words=private_dictionary.txt dont_be_lazy tests README.md CHANGELOG.md docs || true
uv run pylint --score=n --reports=n --rcfile=.pylintrc_spell dont_be_lazy || true
