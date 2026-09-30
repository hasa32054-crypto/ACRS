.PHONY: up down logs seed test test-api test-ui migrate reset ps
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
