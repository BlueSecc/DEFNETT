#!/bin/sh
# Uji integrasi Cyber Intrusion Patrol (state machine skenario + guards).
#
# Prasyarat:
#   docker compose -f compose.yaml -f compose.canary.yaml -f compose.demo-fast.yaml up -d --build
#   (demo-fast mempercepat delay pemulihan jadi 12 detik; tanpa overlay ini
#    skenario positif butuh waktu sesuai DEMO_RECOVERY_DELAY_SECONDS normal)
#
# Output: test-results/test-scenarios.csv + JSON tiap run (dari mesin host).
#
# Variabel lingkungan opsional:
#   COLLECTOR_BASE       default http://127.0.0.1:8090
#   TIMEOUT_POSITIVE_S   default 420
#   TIMEOUT_NEGATIVE_S   default 300
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
results_dir="$root_dir/test-results"
collector_base=${COLLECTOR_BASE:-http://127.0.0.1:8090}
timeout_positive=${TIMEOUT_POSITIVE_S:-420}
timeout_negative=${TIMEOUT_NEGATIVE_S:-300}
csv="$results_dir/test-scenarios.csv"
mkdir -p "$results_dir"

printf 'scenario,run_id,state,verdict,rejection_grade\n' >"$csv"

start_run() {
    # $1 nama skenario -> cetak run_id (2>/dev/null via caller yang menangkap error)
    curl --silent --show-error --fail \
        --request POST "$collector_base/api/demo/scenarios/start" \
        --header 'Content-Type: application/json' \
        --data "{\"scenario\": \"$1\"}" \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["run"]["run_id"])'
}

run_state() {
    # $1 run_id -> cetak state
    curl --silent --show-error --fail \
        "$collector_base/api/demo/scenarios/$1" \
        | python3 -c 'import json, sys; print(json.load(sys.stdin).get("state", ""))'
}

wait_terminal() {
    # $1 run_id, $2 timeout detik -> cetak state terminal, atau return 1 saat timeout
    run_id=$1
    deadline=$(( $(date +%s) + $2 ))
    state=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state=$(run_state "$run_id")
        case "$state" in
            COMPLETE|FAILED|CANCELLED) printf '%s' "$state"; return 0 ;;
        esac
        sleep 2
    done
    return 1
}

assert_prerequisites() {
    python3 - "$collector_base" <<'PY'
import json, sys, urllib.request
base = sys.argv[1].rstrip("/") + "/v1/dashboard"
with urllib.request.urlopen(base, timeout=5) as response:
    data = json.load(response)
analysis = data.get("analysis") or {}
if not analysis.get("auto_repair_enabled"):
    raise SystemExit("Playbook canary belum aktif; jalankan lab dengan compose.canary.yaml.")
PY
}

verify_run() {
    # $1 scenario, $2 expect_state, $3 expected rejection codes (spasi), $4 timeout,
    # $5 attempt (default 1 — retry pace-guardrail maksimal sekali).
    retry_attempt=${5:-1}
    scenario_name=$1
    expect_state=$2
    expected_codes=$3
    timeout_seconds=$4
    printf '%s: memulai run...\n' "$scenario_name"
    response=$(curl --silent --show-error \
        --request POST "$collector_base/api/demo/scenarios/start" \
        --header 'Content-Type: application/json' \
        --data "{\"scenario\": \"$scenario_name\"}") \
        || { printf '%s: start gagal HTTP/400\n' "$scenario_name" >&2; return 1; }
    run_id=$(printf '%s' "$response" \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["run"]["run_id"])')

    state=$(wait_terminal "$run_id" "$timeout_seconds") || {
        printf 'scenario=%s,run_id=%s,state=TIMEOUT,verdict=FAIL,\n' "$scenario_name" "$run_id" >>"$csv"
        printf '%s: melewati batas waktu.\n' "$scenario_name" >&2
        return 1
    }

    curl --silent --show-error --fail \
        "$collector_base/api/demo/scenarios/$run_id" >"$results_dir/$scenario_name.json"

    # Kebijakan laju: bila run ditolak dengan SATU-satunya kegagalan adalah
    # COOLDOWN_ACTIVE dan/atau RATE_LIMIT_REACHED (bersifat sementara),
    # tunggu 20 s dan ulangi MAKSIMAL SEKALI. Penolakan otentik
    # (SURVIVOR_NOT_HEALTHY, EVIDENCE_INSUFFICIENT, dsb.) tidak pernah di-retry.
    retry=$(python3 - "$results_dir/$scenario_name.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
steps = data.get("steps") or []
failed = []
for step in steps:
    if step.get("state") == "POLICY_EVALUATION":
        decision = (step.get("detail") or {}).get("decision") or {}
        failed = [r.get("code") for r in (decision.get("reasons") or []) if not r.get("check")]
        break
print("RETRY" if failed and set(failed) <= {"COOLDOWN_ACTIVE", "RATE_LIMIT_REACHED"} else "NO")
PY
)
    if [ "$retry" = RETRY ]; then
        if [ "$retry_attempt" -ge 2 ]; then
            printf '%s: masih ditolak pace-guardrail setelah satu kali retry; menilai hasil aktual.\n' "$scenario_name" >&2
        else
            printf '%s: pace-guardrail menolak (cooldown/rate-limit); tunggu 20 s dan ulangi sekali.\n' "$scenario_name" >&2
            attempt_grade=$(python3 - "$results_dir/$scenario_name.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
steps = data.get("steps") or []
for step in steps:
    if step.get("state") == "POLICY_EVALUATION":
        decision = (step.get("detail") or {}).get("decision") or {}
        print(" ".join(r.get("code") for r in (decision.get("reasons") or []) if not r.get("check")))
        break
PY
)
            printf 'scenario=%s,run_id=%s,state=%s,verdict=REJECTED_PACE_RETRY_PENDING,rejection_grade=%s\n' \
                "$scenario_name" "$run_id" "$state" "$attempt_grade" >>"$csv"
            sleep 20
            verify_run "$scenario_name" "$expect_state" "$expected_codes" "$timeout_seconds" 2
            return $?
        fi
    fi

    verdict=PASS
    grade=""
    if [ "$state" != "$expect_state" ]; then
        verdict=FAIL
    fi
    rejection=$(python3 - "$results_dir/$scenario_name.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
codes = data.get("rejection_reason") or []
print(" ".join(codes))
PY
)
    grade=$rejection
    if [ "$scenario_name" = containment_allowed ]; then
        positive_ok=$(python3 - "$results_dir/$scenario_name.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
steps = data.get("steps") or []
quarantine = any(step.get("state") == "CANARY_QUARANTINED" for step in steps)
rejoin = any(step.get("state") == "HEALTH_VERIFICATION" for step in steps)
recovery = any(step.get("state") == "RECOVERY" for step in steps)
print("OK" if quarantine and rejoin and recovery else "INCOMPLETE")
PY
)
        if [ "$positive_ok" != OK ]; then
            verdict=FAIL
            grade="$positive_ok $rejection"
        fi
    fi
    for code in $expected_codes; do
        case "$rejection" in
            *"$code"*) ;;
            *) verdict=FAIL; grade="missing:$code" ;;
        esac
    done

    printf 'scenario=%s,run_id=%s,state=%s,verdict=%s,%s\n' \
        "$scenario_name" "$run_id" "$state" "$verdict" "$grade" >>"$csv"
    if [ "$verdict" != PASS ]; then
        printf '%s: FAIL (state=%s, grade=%s)\n' "$scenario_name" "$state" "$grade" >&2
        return 1
    fi
    printf '%s: PASS (state=%s)\n' "$scenario_name" "$state"
}

assert_prerequisites

verify_run containment_allowed COMPLETE "" "$timeout_positive"
verify_run containment_blocked_survivor_down COMPLETE "SURVIVOR_NOT_HEALTHY" "$timeout_negative"
verify_run containment_blocked_evidence_invalid COMPLETE "EVIDENCE_INSUFFICIENT" "$timeout_negative"

printf 'Guard object: start kedua saat run aktif ditolak...\n'
guard_description='containment_blocked_evidence_invalid'
run_id=$(printf 'Starting guard run...\n' >&2; start_run "$guard_description")
sleep 2
second_code=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --request POST "$collector_base/api/demo/scenarios/start" \
    --header 'Content-Type: application/json' \
    --data "{\"scenario\": \"$guard_description\"}")
state=$(wait_terminal "$run_id" "$timeout_negative") || exit 1
if [ "$second_code" != 409 ] || [ "$state" != COMPLETE ]; then
    printf 'scenario=guard_duplicate_start,state=%s,verdict=FAIL,http=%s\n' \
        "$state" "$second_code" >>"$csv"
    printf 'Guard duplicate start GAGAL (http=%s, state=%s).\n' "$second_code" "$state" >&2
    exit 1
fi
printf 'scenario=guard_duplicate_start,state=%s,verdict=PASS,http=%s\n' "$state" "$second_code" >>"$csv"

printf '\nRangkuman:\n'
cat "$csv"
