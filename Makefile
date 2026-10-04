.PHONY: test vet fmt check contract local-up local-down local-health local-seed local-roles local-rls-test

COMPOSE_FILE := deploy/compose/compose.yaml

test:
	GOTOOLCHAIN=local go test ./...

vet:
	GOTOOLCHAIN=local go vet ./...

fmt:
	gofmt -w cmd internal

contract:
	GOTOOLCHAIN=local go test ./internal/contracts/...

check: test vet

local-up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

local-down:
	docker compose -f $(COMPOSE_FILE) down

local-health:
	docker compose -f $(COMPOSE_FILE) ps
	docker compose -f $(COMPOSE_FILE) exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c 'SELECT current_setting('"'"'server_version'"'"') AS postgres_version, (SELECT extversion FROM pg_extension WHERE extname = '"'"'vector'"'"') AS pgvector_version, (SELECT count(*) FROM local_fixtures.tenants) AS synthetic_tenants;'
	docker compose -f $(COMPOSE_FILE) exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
	docker compose -f $(COMPOSE_FILE) exec -T redis redis-cli ping
	docker compose -f $(COMPOSE_FILE) exec -T temporal temporal operator cluster health --address temporal:7233

local-seed:
	docker compose -f $(COMPOSE_FILE) exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -f /docker-entrypoint-initdb.d/10-keel-fixtures.sql

local-roles:
	docker compose -f $(COMPOSE_FILE) exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -f /docker-entrypoint-initdb.d/20-keel-tenant-roles.sql

local-rls-test: local-up local-roles
	@set -eu; \
	test_bin=$$(mktemp /tmp/keel-tenancy-test.XXXXXX); \
	trap 'rm -f "$$test_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-tenancy.test >/dev/null 2>&1 || true' EXIT; \
	GOTOOLCHAIN=local go test -c -o "$$test_bin" ./internal/platform/tenancy; \
	docker cp "$$test_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-tenancy.test; \
	docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	  KEEL_TEST_DATABASE_URL='postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_AGENT_PASSWORD='keel-agent-local-only' \
	  /tmp/keel-tenancy.test -test.run TestPostgreSQLTenantIsolation -test.count=1
