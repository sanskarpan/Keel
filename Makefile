.PHONY: test vet fmt check local-up local-down local-health local-seed

COMPOSE_FILE := deploy/compose/compose.yaml

test:
	GOTOOLCHAIN=local go test ./...

vet:
	GOTOOLCHAIN=local go vet ./...

fmt:
	gofmt -w cmd internal

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
