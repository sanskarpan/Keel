.PHONY: test vet fmt check contract local-up local-down local-health local-seed local-roles local-rls-test local-migration-test local-migrate local-orders-test local-supplier-test local-case-test

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

local-migration-test: local-up local-roles
	@set -eu; \
	test_bin=$$(mktemp /tmp/keel-migrations-test.XXXXXX); \
	trap 'rm -f "$$test_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-migrations.test >/dev/null 2>&1 || true' EXIT; \
	GOTOOLCHAIN=local go test -c -o "$$test_bin" ./internal/platform/migrations; \
	docker cp "$$test_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-migrations.test; \
	docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	  KEEL_TEST_MIGRATION_DATABASE_URL='postgres://keel_local_migrator:keel-migrate-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  /tmp/keel-migrations.test -test.run TestPostgreSQL -test.count=1

local-migrate: local-up local-roles
	@set -eu; \
	app_bin=$$(mktemp /tmp/keel-migrate.XXXXXX); \
	trap 'rm -f "$$app_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-migrate >/dev/null 2>&1 || true' EXIT; \
	GOTOOLCHAIN=local go build -o "$$app_bin" ./cmd/keel; \
	docker cp "$$app_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-migrate; \
	docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	  KEEL_MIGRATION_DATABASE_URL='postgres://keel_local_migrator:keel-migrate-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  /tmp/keel-migrate migrate

local-orders-test: local-migrate
	@set -eu; \
	docker compose -f $(COMPOSE_FILE) exec -T kafka /opt/kafka/bin/kafka-topics.sh \
	  --bootstrap-server localhost:9092 --create --if-not-exists \
	  --topic keel.test.orders.v1 --partitions 3 --replication-factor 1; \
	docker compose -f $(COMPOSE_FILE) exec -T kafka /opt/kafka/bin/kafka-topics.sh \
	  --bootstrap-server localhost:9092 --create --if-not-exists \
	  --topic keel.k17-relay.orders.v1 --partitions 3 --replication-factor 1; \
	docker compose -f $(COMPOSE_FILE) exec -T kafka /opt/kafka/bin/kafka-topics.sh \
	  --bootstrap-server localhost:9092 --create --if-not-exists \
	  --topic keel.k17-consumer.orders.v1 --partitions 3 --replication-factor 1; \
	test_bin=$$(mktemp /tmp/keel-orders-test.XXXXXX); \
	trap 'rm -f "$$test_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-orders.test >/dev/null 2>&1 || true' EXIT; \
	GOTOOLCHAIN=local go test -c -o "$$test_bin" ./internal/orders/postgres; \
	docker cp "$$test_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-orders.test; \
	docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	  KEEL_TEST_DATABASE_URL='postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_WORKER_DATABASE_URL='postgres://keel_local_worker:keel-worker-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_PROJECTOR_DATABASE_URL='postgres://keel_local_projector:keel-projector-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_OPERATOR_DATABASE_URL='postgres://keel_local_operator:keel-operator-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_ADMIN_DATABASE_URL='postgres://postgres:keel-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	  KEEL_TEST_KAFKA_BROKERS='kafka:9092' \
	  KEEL_TEST_KAFKA_TOPIC='keel.test.orders.v1' \
	  /tmp/keel-orders.test -test.run TestPostgreSQL -test.count=1

local-supplier-test: local-migrate
	@set -eu; \
	 test_bin=$$(mktemp /tmp/keel-supplier-test.XXXXXX); \
	 trap 'rm -f "$$test_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-supplier.test >/dev/null 2>&1 || true' EXIT; \
	 GOTOOLCHAIN=local go test -c -o "$$test_bin" ./internal/supplier/intake/postgres; \
	 docker cp "$$test_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-supplier.test; \
	 docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	   KEEL_TEST_DATABASE_URL='postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	   KEEL_TEST_FILE_PROCESSOR_DATABASE_URL='postgres://keel_local_file_processor:keel-file-processor-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	   /tmp/keel-supplier.test -test.run TestPostgreSQLSupplierInvitationAndUploadLifecycle -test.count=1

local-case-test: local-migrate
	@set -eu; \
	 test_bin=$$(mktemp /tmp/keel-case-test.XXXXXX); \
	 trap 'rm -f "$$test_bin"; docker compose -f $(COMPOSE_FILE) exec -T postgres rm -f /tmp/keel-cases.test >/dev/null 2>&1 || true' EXIT; \
	 GOTOOLCHAIN=local go test -c -o "$$test_bin" ./internal/supplier/cases/postgres; \
	 docker cp "$$test_bin" $$(docker compose -f $(COMPOSE_FILE) ps -q postgres):/tmp/keel-cases.test; \
	 docker compose -f $(COMPOSE_FILE) exec -T postgres env \
	   KEEL_TEST_DATABASE_URL='postgres://keel_local_app:keel-app-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	   KEEL_TEST_FILE_PROCESSOR_DATABASE_URL='postgres://keel_local_file_processor:keel-file-processor-local-only@127.0.0.1:5432/postgres?sslmode=disable' \
	   /tmp/keel-cases.test -test.run TestPostgreSQLSupplierCaseEvidenceAndWorkflowIntentLifecycle -test.count=1
