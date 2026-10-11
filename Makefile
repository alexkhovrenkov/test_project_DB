# One-command workflow. Run "make help" to list the targets.
#
#   make demo    set everything up (first time) and run the demonstrations
#   make test    set everything up (first time) and run the automated tests

PYTHON  := .venv/bin/python
COMPOSE := docker compose

.DEFAULT_GOAL := help
.PHONY: help env certs up venv setup demo roles examples experiments test down reset clean lint

help:
	@echo "make demo         start MariaDB 13.1 (first run: also .env, certificates, venv) and run every demonstration"
	@echo "make test         same setup, then run the pytest suite against the real server"
	@echo "make roles        role demo only: the same six actions as each of the four roles"
	@echo "make examples     the standalone SQL tutorial (examples/*.sql)"
	@echo "make experiments  the advanced security experiments (experiments/*.sql)"
	@echo "make down         stop the server (keeps the data)"
	@echo "make reset        stop the server and DELETE its data; next 'make up' starts from scratch"
	@echo "make clean        reset + delete .env, certificates and the virtual environment"
	@echo "make lint         shellcheck the shell scripts (needs shellcheck installed)"

env:
	bash scripts/init_env.sh

certs:
	@if [ ! -f certs/server-key.pem ]; then bash scripts/generate_certs.sh; fi
	@chmod 600 certs/*-key.pem   # also repairs keys created by older versions of this project

up: env certs
	$(COMPOSE) up -d --wait

.venv/.installed: requirements.txt requirements-dev.txt
	python3 -m venv .venv
	$(PYTHON) -m pip install --quiet --upgrade pip
	$(PYTHON) -m pip install --quiet -r requirements-dev.txt
	touch $@

venv: .venv/.installed

setup: up venv

roles: setup
	$(PYTHON) app/demo.py

examples: setup
	$(PYTHON) app/sqlrunner.py examples/

experiments: setup
	$(PYTHON) app/sqlrunner.py experiments/

demo: roles examples experiments
	@echo
	@echo "Demo finished: every step above ended in PASS. Run 'make test' for the pytest suite."

test: setup
	$(PYTHON) -m pytest

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

clean: reset
	rm -rf .venv certs .env .pytest_cache

lint:
	shellcheck scripts/*.sh sql/04_users.sh
