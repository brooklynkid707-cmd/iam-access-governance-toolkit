PY ?= python3

.PHONY: setup data audit simulate rolemine test clean all

setup:            ## install dependencies
	$(PY) -m pip install --break-system-packages -r requirements.txt

data:             ## regenerate the synthetic directory export
	$(PY) scripts/generate_sample_data.py --out data/directory.json --users 250 --seed 20261017

audit:            ## run the full audit and write reports/
	$(PY) -m iamtk audit data/directory.json --out reports/

simulate:         ## example policy simulation
	$(PY) -m iamtk simulate data/directory.json --user efairweather --action approve --resource finance.payments

rolemine:         ## suggest roles from clustered permission sets
	$(PY) -m iamtk rolemine data/directory.json --threshold 0.7 --min-members 3

test:             ## run the test suite
	$(PY) -m pytest -q

clean:
	rm -rf reports/* .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
	touch reports/.gitkeep

all: data audit test
