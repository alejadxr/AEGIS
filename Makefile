# AEGIS CI parity — mirrors .github/workflows/ci.yml exactly so local runs
# catch failures before push.
#
# Usage:
#   make ci-check        # run all three CI jobs in sequence
#   make lint-backend    # ruff advisory lint (--exit-zero)
#   make build-frontend  # Next.js production build
#   make compose-check   # docker compose config validation

.PHONY: ci-check lint-backend build-frontend compose-check

## Run every check the CI workflow runs (in the same order).
ci-check: lint-backend build-frontend compose-check

## Advisory ruff lint — prints findings but never exits non-zero.
lint-backend:
	cd backend && pip install --quiet ruff && ruff check app/ --select E,F,W --ignore E501 --exit-zero

## Next.js production build (clean install to match CI).
build-frontend:
	cd frontend && npm install && npm run build

## Validate docker-compose configuration.
compose-check:
	docker compose config --quiet
