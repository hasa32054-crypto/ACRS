.PHONY: up down logs seed test test-api test-ui migrate reset ps hassan-test hassan-repro
up:        ## build and start postgres, redis, backend, frontend
	docker compose up --build -d
	@echo "Console: http://localhost:8080   API docs: http://localhost:8000/docs"
down:
	docker compose down
logs:
	docker compose logs -f backend
seed:      ## idempotent: 20 assets + demo users
	docker compose exec backend python -m app.seed
migrate:
	docker compose exec backend alembic upgrade head
test:      ## full backend suite inside the container (engines, lifecycle, phase B, API)
	docker compose exec backend python -m pytest -q
test-api:
	docker compose exec backend python -m pytest -q tests/test_api.py
test-ui:   ## frontend unit tests + typecheck (needs Node 20 locally)
	cd frontend && npm install --no-audit --no-fund && npm test && npm run typecheck
reset:     ## wipe everything including the database volume
	docker compose down -v
ps:
	docker compose ps

HASSAN_TESTS = tests.test_qacrs tests.test_qacrs_v3 tests.test_qacrs_v7 tests.test_hassan_engine \
               tests.test_executor_v8 tests.test_realism_v8 tests.test_hassan_service tests.test_hassan_v9
hassan-test:   ## Q-ACRS / HASSAN unit tests (standard library only, no Docker)
	cd backend && python3 -m unittest $(HASSAN_TESTS)
hassan-repro:  ## regenerate the core v7/v8 results (no IBM, no root sandbox, no 25-min QAOA seeds)
	cd backend && start=$$(date +%s) && python3 -m unittest $(HASSAN_TESTS) && python3 -m qacrs.phase9_v7 && \
	  python3 -m qacrs.phase10_adversarial && python3 -m qacrs.phase11_executor && \
	  python3 -m qacrs.phase12_realism_scale && python3 -m qacrs.phase13_integration && \
	  echo "hassan-repro: $$(( $$(date +%s) - start )) s"
	git status --short backend/qacrs/results
