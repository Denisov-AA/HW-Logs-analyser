PROJECT_NAME := Log_Analyser
POETRY := poetry


install:
	poetry config virtualenvs.create false
	$(POETRY) install

ruff:
	$(POETRY) run ruff check

black:
	$(POETRY) run black --check .

isort:
	$(POETRY) run isort --check-only .

mypy:
	$(POETRY) run mypy ./src/log_analyser.py

all-checks:
	install
	ruff
	black
	isort
	mypy

log-analyse:
	python src/log_analyser.py

run-tests:
	python -m unittest tests/test_log_analyser.py