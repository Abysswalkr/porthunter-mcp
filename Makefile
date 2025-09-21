.PHONY: venv install run bench

venv:
	python -m venv .venv

install:
	.\.venv\Scripts\python -m pip install -U pip
	.\.venv\Scripts\python -m pip install -e .

run:
	set PORT_HUNTER_TOKEN=TEST_TOKEN && \
	set PORT_HUNTER_ALLOWED_DIR=%CD% && \
	.\.venv\Scripts\python -m porthunter.server

bench:
	.\.venv\Scripts\python scripts\benchmark_porthunter.py tiny.pcap
