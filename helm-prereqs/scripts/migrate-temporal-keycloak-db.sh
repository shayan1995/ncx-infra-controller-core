#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# =============================================================================
# migrate-temporal-keycloak-db.sh — one-time cutover of Temporal and/or
# Keycloak from the legacy standalone postgres.postgres StatefulSet onto the
# shared nico-pg-cluster.
#
# This is a stop-the-world dump/restore, not a zero-downtime migration:
# Temporal and/or Keycloak are scaled to zero for the duration so no writes
# land on postgres.postgres after the dump is taken. Expect Temporal workflow
# processing and Keycloak logins to be unavailable while this runs.
#
# Prerequisites (this script checks and refuses to proceed otherwise):
#   1. temporal.enabled and/or keycloak.enabled set true in
#      helm-prereqs/values.yaml, and `helmfile sync` (or setup.sh through
#      phase 6) already applied — this creates the temporal.nico/keycloak.nico
#      users and empty temporal/temporal_visibility/keycloak databases on
#      nico-pg-cluster, and the ESO ClusterExternalSecrets that sync their
#      credentials.
#   2. The legacy postgres.postgres StatefulSet is still running with the
#      data to migrate.
#
# After this script succeeds, re-run setup.sh: phases 7d/7f detect the
# enabled toggles and point Temporal/Keycloak at nico-pg-cluster, then scale
# the workloads back up.
#
# Usage:
#   ./migrate-temporal-keycloak-db.sh [--db temporal|keycloak|both] [--dry-run]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREREQS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

DB_TARGET="both"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)
            DB_TARGET="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ "${DB_TARGET}" != "temporal" && "${DB_TARGET}" != "keycloak" && "${DB_TARGET}" != "both" ]]; then
    echo "ERROR: --db must be temporal, keycloak, or both (got: ${DB_TARGET})" >&2
    exit 1
fi

_run() {
    if "${DRY_RUN}"; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}

echo "=== migrate-temporal-keycloak-db.sh (--db ${DB_TARGET}${DRY_RUN:+, dry-run}) ==="

# ---------------------------------------------------------------------------
# Preflight: legacy postgres pod
# ---------------------------------------------------------------------------
LEGACY_PG_POD="$(kubectl get pods -n postgres -l app=postgres \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "${LEGACY_PG_POD}" ]]; then
    echo "ERROR: no legacy postgres pod found (app=postgres in the postgres namespace) — nothing to migrate from." >&2
    exit 1
fi
echo "Legacy postgres pod: ${LEGACY_PG_POD}"

# ---------------------------------------------------------------------------
# Preflight: nico-pg-cluster master pod
# ---------------------------------------------------------------------------
NICO_PG_POD="$(kubectl get pods -n postgres \
    -l cluster-name=nico-pg-cluster,spilo-role=master \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "${NICO_PG_POD}" ]]; then
    echo "ERROR: no nico-pg-cluster master pod found (cluster-name=nico-pg-cluster,spilo-role=master in the postgres namespace)." >&2
    echo "  Ensure postgresql.enabled=true in helm-prereqs/values.yaml and the nico-prereqs release has synced." >&2
    exit 1
fi
echo "nico-pg-cluster master pod: ${NICO_PG_POD}"

# ---------------------------------------------------------------------------
# Preflight: target database/user already provisioned by the postgres
# operator (i.e. the corresponding *.enabled toggle was applied before this
# script ran).
# ---------------------------------------------------------------------------
_require_target_db() {
    local _db="$1"
    if ! kubectl exec -n postgres "${NICO_PG_POD}" -- \
        psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${_db}'" 2>/dev/null | grep -q 1; then
        echo "ERROR: database '${_db}' does not exist on nico-pg-cluster yet." >&2
        echo "  Set the matching *.enabled toggle in ${PREREQS_DIR}/values.yaml and run 'helmfile sync' (or setup.sh) first." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Migrate one database: scale down consumers, dump from the legacy pod,
# restore into nico-pg-cluster, fix ownership on the restored objects.
#
# Args: <db-name> <owner-role> <deployment-namespace> <deployment-name>...
# ---------------------------------------------------------------------------
_migrate_db() {
    local _db="$1" _owner="$2" _ns="$3"
    shift 3
    local _deployments=("$@")

    echo ""
    echo "--- Migrating database: ${_db} (owner: ${_owner}) ---"
    _require_target_db "${_db}"

    local _replicas=()
    local _dep
    for _dep in "${_deployments[@]}"; do
        local _cur
        _cur="$(kubectl get deploy "${_dep}" -n "${_ns}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 0)"
        _replicas+=("${_cur}")
        echo "Scaling down ${_ns}/${_dep} (was ${_cur} replicas)..."
        _run kubectl scale deploy "${_dep}" -n "${_ns}" --replicas=0
    done
    if ! "${DRY_RUN}" && [[ ${#_deployments[@]} -gt 0 ]]; then
        for _dep in "${_deployments[@]}"; do
            kubectl rollout status deploy/"${_dep}" -n "${_ns}" --timeout=120s || true
        done
    fi

    echo "Dumping ${_db} from ${LEGACY_PG_POD} and restoring into ${NICO_PG_POD}..."
    if "${DRY_RUN}"; then
        echo "  [dry-run] kubectl exec -n postgres ${LEGACY_PG_POD} -- pg_dump -U postgres -Fc --no-owner --no-acl ${_db} |" \
             "kubectl exec -i -n postgres ${NICO_PG_POD} -- pg_restore -U postgres -d ${_db} --no-owner --clean --if-exists"
    else
        kubectl exec -n postgres "${LEGACY_PG_POD}" -- \
            pg_dump -U postgres -Fc --no-owner --no-acl "${_db}" | \
            kubectl exec -i -n postgres "${NICO_PG_POD}" -- \
                pg_restore -U postgres -d "${_db}" --no-owner --clean --if-exists
    fi

    echo "Fixing ownership on restored objects in ${_db}..."
    _run kubectl exec -n postgres "${NICO_PG_POD}" -- \
        psql -U postgres -d "${_db}" -c "REASSIGN OWNED BY postgres TO \"${_owner}\";"
    _run kubectl exec -n postgres "${NICO_PG_POD}" -- \
        psql -U postgres -d "${_db}" -c "GRANT ALL ON SCHEMA public TO \"${_owner}\";"

    echo "Restoring replica counts for ${_ns}..."
    local _i=0
    for _dep in "${_deployments[@]}"; do
        _run kubectl scale deploy "${_dep}" -n "${_ns}" --replicas="${_replicas[${_i}]}"
        _i=$((_i + 1))
    done

    echo "--- ${_db} migration complete ---"
}

if [[ "${DB_TARGET}" == "temporal" || "${DB_TARGET}" == "both" ]]; then
    _migrate_db "temporal" "temporal.nico" "temporal" \
        temporal-frontend temporal-history temporal-matching temporal-worker
    _migrate_db "temporal_visibility" "temporal.nico" "temporal" \
        temporal-frontend temporal-history temporal-matching temporal-worker
fi

if [[ "${DB_TARGET}" == "keycloak" || "${DB_TARGET}" == "both" ]]; then
    _KEYCLOAK_NS="${KEYCLOAK_NS:-nico-rest}"
    _migrate_db "keycloak" "keycloak.nico" "${_KEYCLOAK_NS}" keycloak
fi

echo ""
echo "=== Migration complete ==="
echo "Next steps:"
if [[ "${DB_TARGET}" == "temporal" || "${DB_TARGET}" == "both" ]]; then
    echo "  - Confirm temporal.enabled: true in ${PREREQS_DIR}/values.yaml"
fi
if [[ "${DB_TARGET}" == "keycloak" || "${DB_TARGET}" == "both" ]]; then
    echo "  - Confirm keycloak.enabled: true in ${PREREQS_DIR}/values.yaml"
fi
echo "  - Re-run setup.sh so phases 7d/7f point Temporal/Keycloak at nico-pg-cluster and scale workloads back up"
echo "  - Once verified, the legacy temporal/temporal_visibility/keycloak databases on postgres.postgres can be dropped"
