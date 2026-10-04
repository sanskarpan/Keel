#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${KEEL_TEST_KAFKA_IMAGE:-apache/kafka:4.3.1}
container=keel-kafka-secure-contract
work=$(mktemp -d)
cleanup() {
  status=$?
  if [[ "$status" != 0 ]] && docker inspect "$container" >/dev/null 2>&1; then
    docker logs "$container" >&2
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$work/ca.key" -out "$work/ca.crt" -subj "/CN=Keel test CA"
openssl req -newkey rsa:2048 -nodes -keyout "$work/broker.key" \
  -out "$work/broker.csr" -subj "/CN=localhost"
cat >"$work/broker.ext" <<'EOF'
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl x509 -req -in "$work/broker.csr" -CA "$work/ca.crt" \
  -CAkey "$work/ca.key" -CAcreateserial -days 2 -out "$work/broker.crt" \
  -extfile "$work/broker.ext"
openssl pkcs12 -export -in "$work/broker.crt" -inkey "$work/broker.key" \
  -out "$work/broker.p12" -name keel-kafka-test -passout pass:keel-test-keystore
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$work/wrong-ca.key" -out "$work/wrong-ca.crt" -subj "/CN=Wrong Keel test CA"
printf '%s' 'keel-test-keystore' >"$work/keystore-credentials"
printf '%s' 'keel-test-keystore' >"$work/key-credentials"
cat >"$work/kafka_server_jaas.conf" <<'EOF'
KafkaServer { org.apache.kafka.common.security.scram.ScramLoginModule required username="broker" password="broker" serviceName="kafka"; };
EOF
chmod 711 "$work"
chmod 644 "$work/ca.crt" "$work/wrong-ca.crt" "$work/broker.p12" \
  "$work/keystore-credentials" "$work/key-credentials" "$work/kafka_server_jaas.conf"
rm -f "$work/ca.key" "$work/broker.key" "$work/broker.csr" \
  "$work/broker.ext" "$work/wrong-ca.key"

docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --name "$container" --network host \
  --volume "$work:/etc/kafka/secrets:ro" \
  --env CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk \
  --env KAFKA_NODE_ID=1 \
  --env KAFKA_PROCESS_ROLES=broker,controller \
  --env KAFKA_LISTENERS=INTERNAL://:9092,CONTROLLER://:9093,SETUP://:29092,SASL_SSL://:29093 \
  --env KAFKA_ADVERTISED_LISTENERS=INTERNAL://localhost:9092,SETUP://localhost:29092,SASL_SSL://localhost:29093 \
  --env KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT,SETUP:PLAINTEXT,SASL_SSL:SASL_SSL \
  --env KAFKA_INTER_BROKER_LISTENER_NAME=INTERNAL \
  --env KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  --env KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  --env KAFKA_AUTO_CREATE_TOPICS_ENABLE=false \
  --env KAFKA_DEFAULT_REPLICATION_FACTOR=1 \
  --env KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  --env KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
  --env KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
  --env KAFKA_MIN_INSYNC_REPLICAS=1 \
  --env KAFKA_NUM_PARTITIONS=3 \
  --env KAFKA_SASL_ENABLED_MECHANISMS=SCRAM-SHA-512 \
  --env KAFKA_LISTENER_NAME_SASL_SSL_SASL_ENABLED_MECHANISMS=SCRAM-SHA-512 \
  --env KAFKA_SSL_KEYSTORE_TYPE=PKCS12 \
  --env KAFKA_SSL_KEYSTORE_FILENAME=broker.p12 \
  --env KAFKA_SSL_KEYSTORE_TYPE=PKCS12 \
  --env KAFKA_SSL_KEYSTORE_CREDENTIALS=keystore-credentials \
  --env KAFKA_SSL_KEY_CREDENTIALS=key-credentials \
  --env KAFKA_OPTS=-Djava.security.auth.login.config=/etc/kafka/secrets/kafka_server_jaas.conf \
  "$image"

ready=false
for _ in $(seq 1 60); do
  if docker run --rm --network host --entrypoint /opt/kafka/bin/kafka-topics.sh "$image" \
    --bootstrap-server 127.0.0.1:29092 --list >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != true ]]; then
  docker logs "$container"
  echo "secure test Kafka did not become ready" >&2
  exit 1
fi

for user in keel-test-user keel-rotated-user; do
  password=keel-test-password
  [[ "$user" == keel-rotated-user ]] && password=keel-rotated-password
  timeout 30s docker run --rm --network host --entrypoint /opt/kafka/bin/kafka-configs.sh "$image" \
    --bootstrap-server 127.0.0.1:29092 --alter --add-config "SCRAM-SHA-512=[iterations=8192,password=$password]" \
    --entity-type users --entity-name "$user"
done
timeout 30s docker run --rm --network host --entrypoint /opt/kafka/bin/kafka-topics.sh "$image" \
  --bootstrap-server 127.0.0.1:29092 --create --if-not-exists \
  --topic keel.security.orders.v1 --partitions 3 --replication-factor 1

export KEEL_TEST_KAFKA_TLS_BROKERS=localhost:29093
export KEEL_TEST_KAFKA_TLS_TOPIC=keel.security.orders.v1
export KEEL_TEST_KAFKA_TLS_CA="$work/ca.crt"
export KEEL_TEST_KAFKA_TLS_WRONG_CA="$work/wrong-ca.crt"
export KEEL_TEST_KAFKA_TLS_USERNAME=keel-test-user
export KEEL_TEST_KAFKA_TLS_PASSWORD=keel-test-password
export KEEL_TEST_KAFKA_TLS_ROTATED_USERNAME=keel-rotated-user
export KEEL_TEST_KAFKA_TLS_ROTATED_PASSWORD=keel-rotated-password
cd "$repo_root"
go test ./internal/platform/kafkarelay -run '^TestAuthenticatedKafkaBrokerIntegration$' -count=1 -v
