#!/usr/bin/env sh
# Post-deploy smoke test: ./scripts/smoke.sh https://api.example.com https://app.example.com
set -eu
API=${1:-http://localhost:8000}
WEB=${2:-http://localhost:3000}
check() { code=$(curl -s -o /dev/null -w '%{http_code}' "$1"); [ "$code" = "$2" ] || { echo "FAIL $1 -> $code (want $2)"; exit 1; }; echo "ok   $1"; }
check "$API/v1/health" 200
check "$API/v1/ready" 200
check "$API/openapi.json" 200
check "$API/v1/incidents" 401
check "$WEB/login" 200
check "$WEB/api/health" 200
echo "smoke tests passed"
