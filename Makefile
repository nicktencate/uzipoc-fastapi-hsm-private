venv: .venv/make_venv_complete ## Create virtual environment
.venv/make_venv_complete:
	python3 -m venv .venv
	. .venv/bin/activate && ${env} pip install -U pip
	. .venv/bin/activate && ${env} pip install -Ur requirements.txt
	. .venv/bin/activate && ${env} pip install -Ur requirements-dev.txt
	touch .venv/make_venv_complete

pip-compile: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements.in
	. .venv/bin/activate && ${env} python3 -m piptools compile requirements-dev.in

pip-sync: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt

pip-sync-dev: ## synchronizes the .venv with the state of requirements.txt
	. .venv/bin/activate && ${env} python3 -m piptools sync requirements.txt requirements-dev.txt

lint: venv  ## Do basic linting
	@. .venv/bin/activate && ${env} pylint app 

check-types: venv ## Check for type issues with mypy
	@. .venv/bin/activate && ${env} python3 -m mypy --check app

run:
	. .venv/bin/activate && ${env} python3 -m hypercorn app.main:app --reload -b 0
