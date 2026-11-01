.PHONY: install test lint format typecheck check samples examples docker run-docker clean

PY ?= python

install:           ## editable install with dev tools and the AWS extra
	$(PY) -m pip install -e ".[dev,aws]"

test:
	$(PY) -m pytest

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check . --fix

typecheck:
	mypy src

check: lint typecheck test   ## everything CI runs

samples:           ## regenerate the synthetic sample logs (deterministic)
	$(PY) scripts/generate_samples.py

examples:          ## regenerate the example reports from the samples
	sh scripts/make_examples.sh

docker:
	docker build -t ai-devops-incident-analyzer:local .

run-docker:        ## analyse the bundled samples inside the container
	docker run --rm ai-devops-incident-analyzer:local analyze /opt/samples --no-color

clean:
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov *.egg-info
