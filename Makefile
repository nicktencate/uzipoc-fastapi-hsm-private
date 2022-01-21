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
	@. .venv/bin/activate && ${env} python3 -m pylint app tests
	@. .venv/bin/activate && ${env} python3 -m black --check app tests

check-types: venv ## Check for type issues with mypy
	@. .venv/bin/activate && ${env} python3 -m mypy --check app tests

fix:
	@. .venv/bin/activate && ${env} python3 -m black app tests

run:
	. .venv/bin/activate && ${env} python3 -m hypercorn app.main:app --reload -b 0

test:
	bash ./bootstrap.sh
	SOFTHSM2_CONF=./softhsm2.conf . .venv/bin/activate && ${env} pytest -vvv

testrun:
	bash ./bootstrap.sh
	SOFTHSM2_CONF=./softhsm2.conf . .venv/bin/activate && ${env} python3 -m hypercorn app.main:app --reload -b 0

runtest:
	./tests/genopensslkeys.sh
	. .venv/bin/activate && ${env} python3 -m tests.run
	@for cert in tests/test-cert-*.pem;do openssl verify -CAfile $$cert $$cert;done

runtest-dev:
	. .venv/bin/activate && ${env} python3 -m tests.run dev
	@for cert in tests/test-cert-*.pem;do openssl verify -CAfile $$cert $$cert;done

.bootstrap:
	bash ./bootstrap.sh
	@touch .bootstrap

setup: venv .bootstrap
