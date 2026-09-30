.PHONY: help setup download-all download transform-all transform sample test-smoke test-full test-unit clean

PYTHON := .venv/bin/python
UV := uv

help:
	@echo "=========================================================="
	@echo " Faraday Laya Guard: Security Benchmark Pipeline Commands"
	@echo "=========================================================="
	@echo "  make setup            Initialize venv and install dependencies"
	@echo "  make download-all     Download all benchmark datasets"
	@echo "  make download SOURCE=<key>  Download specific dataset (e.g. SOURCE=seclists)"
	@echo "  make transform-all    Transform raw data into Parquet files"
	@echo "  make sample SIZE=2000 Generate balanced sample Parquet"
	@echo "  make test-smoke       Run benchmark against smoke_test_2k.parquet"
	@echo "  make test-full        Run benchmark against master_benchmark.parquet"
	@echo "  make test-unit        Run unit tests"
	@echo "  make clean            Clean cache and temporary files"

setup:
	$(UV) venv
	$(UV) pip install -e ".[dev]"

download-all:
	$(PYTHON) scripts/download_raw.py --all

download:
	@if [ -z "$(SOURCE)" ]; then echo "❌ Error: Specify SOURCE=<key>. Example: make download SOURCE=seclists"; exit 1; fi
	$(PYTHON) scripts/download_raw.py --source $(SOURCE)

transform-all:
	$(PYTHON) scripts/transform_to_parquet.py --all

transform:
	$(PYTHON) scripts/transform_to_parquet.py

sample:
	$(PYTHON) scripts/sample_dataset.py --size $(if $(SIZE),$(SIZE),2000)

test-smoke:
	$(PYTHON) benchmark_runner.py --dataset data/processed/smoke_test_2k.parquet --model $(if $(MODEL),$(MODEL),laya-mlx)

test-full:
	$(PYTHON) benchmark_runner.py --dataset data/processed/master_benchmark.parquet --model $(if $(MODEL),$(MODEL),laya-mlx)

test-unit:
	.venv/bin/pytest -v tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache
