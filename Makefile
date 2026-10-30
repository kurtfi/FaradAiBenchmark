.PHONY: help setup download-all download transform-all transform sample test-smoke test-full test-unit web quickstart setup-check clean

PYTHON := .venv/bin/python
UV := uv

help:
	@echo "════════════════════════════════════════════════════════════"
	@echo " 🛡️  Farad Ai Benchmark: Security Benchmark Pipeline"
	@echo "════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  Onboarding:"
	@echo "    make quickstart         One-command bootstrap and launch dashboard"
	@echo "    make setup              Initialize venv and install dependencies"
	@echo ""
	@echo "  Setup & Data:"
	@echo "    make download-all       Download all benchmark datasets"
	@echo "    make download SOURCE=x  Download specific dataset (e.g. SOURCE=seclists)"
	@echo "    make transform-all      Transform raw data into Parquet files"
	@echo "    make sample SIZE=2000   Generate balanced sample Parquet"
	@echo ""
	@echo "  Benchmark:"
	@echo "    make test-smoke         Run benchmark against Farad-Decision-Bench-v1.0"
	@echo "    make test-full          Run benchmark against master_benchmark.parquet"
	@echo "    make test-unit          Run unit tests"
	@echo ""
	@echo "  Dashboard:"
	@echo "    make web                Launch web dashboard on http://localhost:8765"
	@echo "    make web PORT=9000      Launch on custom port"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make clean              Clean cache and temporary files"

setup-check:
	@which $(UV) >/dev/null 2>&1 || (echo "❌ Error: 'uv' not found. Please install uv: https://astral.sh/uv" && exit 1)
	@if [ ! -d .venv ]; then \
		echo "⚙️ Initializing virtual environment..."; \
		$(UV) venv && $(UV) pip install -e ".[dev]"; \
	fi

quickstart: setup-check
	@echo "🚀 Launching Farad Ai Benchmark..."
	@if [ ! -f data/processed/farad_decision_bench_v1.parquet ] && [ ! -f data/processed/smoke_test_2k.parquet ]; then \
		echo "📦 Generating Farad-Decision-Bench-v1.0 benchmark dataset..."; \
		$(PYTHON) scripts/sample_dataset.py --size 2000; \
	fi
	@echo "🛡️  Farad Ai Benchmark Dashboard → http://localhost:$(if $(PORT),$(PORT),8765)"
	$(PYTHON) -m uvicorn web.app:app --host 0.0.0.0 --port $(if $(PORT),$(PORT),8765) --reload

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
	$(PYTHON) benchmark_runner.py --dataset data/processed/farad_decision_bench_v1.parquet --model $(if $(MODEL),$(MODEL),laya-mlx)

test-full:
	$(PYTHON) benchmark_runner.py --dataset data/processed/master_benchmark.parquet --model $(if $(MODEL),$(MODEL),laya-mlx)

test-unit:
	$(PYTHON) -m pytest -v tests/

web:
	@echo "🛡️  Farad Ai Benchmark Dashboard → http://localhost:$(if $(PORT),$(PORT),8765)"
	$(PYTHON) -m uvicorn web.app:app --host 0.0.0.0 --port $(if $(PORT),$(PORT),8765) --reload

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache

