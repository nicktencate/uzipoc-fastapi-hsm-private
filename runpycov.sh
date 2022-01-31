#!/bin/bash
export SOFTHSM2_CONF=${SOFTHSM2_CONF:-$(pwd)/softhsm2.conf}  
. .venv/bin/activate && pytest -vvv --cov=app --cov-report term-missing $*
