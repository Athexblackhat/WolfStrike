# WOLFSTRIKE Makefile
# Author: ATHEX BLACK HAT | Team: Wolf Intelligence PK

.PHONY: help install clean test run

help:
	@echo "WOLFSTRIKE Commands"
	@echo "  make install    Install dependencies"
	@echo "  make clean      Clean cache files"
	@echo "  make run        Run with example target"

install:
	pip install -r requirements.txt

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

run:
	python wolfstrike.py --target example.com
