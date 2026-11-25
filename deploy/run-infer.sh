#!/usr/bin/env bash
set -euo pipefail
SENSOR_HOST="${SENSOR_HOST:-zeek@192.168.230.130}"
SENSOR_LOGS="${SENSOR_LOGS:-/opt/zeek/logs/current}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="/opt/ndr/work/$RUN_ID"
mkdir -p "$WORK" /opt/ndr/zeek/current
exec 9>/opt/ndr/state/infer.lock
flock -n 9 || exit 0
rsync -a --delete "$SENSOR_HOST:$SENSOR_LOGS/" /opt/ndr/zeek/current/
docker run --rm --network host \
  --env-file /opt/ndr/ndr.env \
  -v /opt/ndr/zeek/current:/data/zeek/current:ro \
  -v /opt/ndr/http_ca.crt:/etc/ndr/http_ca.crt:ro \
  -v "$WORK":/work \
  -v /opt/ndr/models:/models:ro \
  -v /opt/ndr/smoke:/opt/ndr/smoke:ro \
  ndr-ml:0.2.0 infer \
  --raw /data/zeek/current \
  --models /models \
  --workdir /work \
  --window-minutes 10 \
  --export-elk
