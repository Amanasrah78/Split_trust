#!/usr/bin/env bash
set -euo pipefail

make_registry() {
    local n="$1"
    local registry=""
    local i

    for ((i=1; i<=n; i++)); do
        if [[ -n "$registry" ]]; then
            registry+=","
        fi
        registry+="did:iota:gateway-${i}"
    done

    printf '%s' "$registry"
}

result_exists() {
    local run_id="$1"

    find results \
        -maxdepth 1 \
        -type f \
        -name "*${run_id}*" \
        -print -quit 2>/dev/null |
        grep -q .
}

configure_domains() {
    local n="$1"

    export REGISTERED_GATEWAY_DIDS
    REGISTERED_GATEWAY_DIDS="$(make_registry "$n")"

    echo
    echo "============================================================"
    echo "Configuring N=${n} logical domains"
    echo "Policy relationships: $((n * (n - 1)))"
    echo "============================================================"

    docker compose up -d --force-recreate sac gateway-b
    sleep 2
}

run_trial() {
    local n="$1"
    local run="$2"
    local run_id="multidomain-d${n}-run${run}"

    if result_exists "$run_id"; then
        echo
        echo "SKIP: existing result found for ${run_id}"
        return
    fi

    echo
    echo "------------------------------------------------------------"
    echo "Running ${run_id}"
    echo "N=${n}, C=10, requests=1000, warmup=100"
    echo "------------------------------------------------------------"

    docker compose run --rm loadgen \
        python -m app.benchmark \
        --mode sac \
        --domains "$n" \
        --warmup 100 \
        --requests 1000 \
        --concurrency 10 \
        --run-id "$run_id"

    echo "Completed ${run_id}"
}

for n in 5 10 25 50; do

    if [[ "$n" -eq 5 ]]; then
        first_run=4
    else
        first_run=1
    fi

    configure_domains "$n"

    for ((run=first_run; run<=5; run++)); do

        if (( run > first_run )); then
            echo
            echo "Restarting SAC and Gateway B before next trial..."
            docker compose restart sac gateway-b
            sleep 2
        fi

        run_trial "$n" "$run"
    done
done

echo
echo "============================================================"
echo "Multi-domain scalability campaign completed."
echo "Expected completed configuration set:"
echo "  N=2  : runs 1-5 already completed"
echo "  N=5  : runs 1-5"
echo "  N=10 : runs 1-5"
echo "  N=25 : runs 1-5"
echo "  N=50 : runs 1-5"
echo "============================================================"
