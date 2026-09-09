#!/usr/bin/env python3
"""Verifica lectura MySQL y filtrado multi-tenant del listado (sin imprimir secretos)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SERVER))

try:
    from dotenv import dotenv_values, load_dotenv
except ImportError:
    load_dotenv = None  # type: ignore
    dotenv_values = None  # type: ignore

if load_dotenv and dotenv_values:
    load_dotenv(SERVER / ".env")
    ingress = dotenv_values(SERVER / ".env.robin-ingress")
    for key, val in ingress.items():
        if val is not None and str(val).strip():
            os.environ[key] = str(val).strip()

os.environ.setdefault("MYSQL_DISABLED", "0")

from lib.agent_store import init_agent_store, list_agents, reset_agent_store
from controllers import _agent_payload, _stored_agents_for_owner
from lib.ruvic_user import owner_ids_from_jwt, user_id_candidates_for_jwt


def _simulate_list(sub: str) -> list[str]:
    fake_user = {"sub": sub, "_access_token": "test"}
    ids = owner_ids_from_jwt(fake_user)
    rows = _stored_agents_for_owner(ids, fake_user)
    return [str(r.get("agent_id") or "") for r in rows]


def main() -> int:
    host = (os.getenv("MYSQL_HOST") or "").strip()
    db = (os.getenv("MYSQL_DATABASE") or "").strip()
    print(f"mysql_host={host!r} database={db!r} disabled={os.getenv('MYSQL_DISABLED')}")

    reset_agent_store()
    try:
        init_agent_store()
    except Exception as e:
        print(f"init_failed: {type(e).__name__}: {e}")
        return 1

    all_rows = list_agents()
    print(f"db_total_agents={len(all_rows)}")

    subs: list[str] = []
    for row in all_rows:
        uid = str(row.get("user_id") or "").strip()
        if uid and uid not in subs:
            subs.append(uid)
        slim = {
            "agent_id": row.get("agent_id"),
            "user_id": row.get("user_id"),
            "client_id": row.get("client_id"),
        }
        print("row", json.dumps(slim, ensure_ascii=False))

    if subs:
        a, b = subs[0], subs[1] if len(subs) > 1 else subs[0]
        list_a = _simulate_list(a)
        list_b = _simulate_list(b)
        print(f"scoped_sub_a={a!r} agents={list_a}")
        print(f"scoped_sub_b={b!r} agents={list_b}")
        if a != b:
            overlap = set(list_a) & set(list_b)
            print(f"overlap={sorted(overlap)} ok={not overlap}")

    if all_rows:
        sample = all_rows[0]
        payload = _agent_payload(sample, online=False)
        print(
            "sample_payload",
            json.dumps(
                {k: payload[k] for k in ("agent_id", "user_id", "online")},
                ensure_ascii=False,
            ),
        )

    fake = {"sub": "nonexistent-sub", "_access_token": "test"}
    ids = owner_ids_from_jwt(fake)
    candidates = user_id_candidates_for_jwt(fake, ids)
    filtered = _stored_agents_for_owner(ids, fake)
    print(f"unknown_sub candidates={candidates!r} filtered={len(filtered)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
