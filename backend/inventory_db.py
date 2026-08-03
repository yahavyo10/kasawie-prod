"""
Connects to a Postgres database holding the user's own network device
inventory. Fetches the full inventory so it can be handed to the LLM
alongside a CVE identified in phases 1/2 -- the LLM reasons about which
devices could be exposed using its own knowledge of that CVE, rather than
this module doing deterministic keyword matching. This module's job is just:
connect, fetch, and group by product signature so the LLM's job stays small
regardless of fleet size.

Fully server-side configured via environment variables (see .env) -- there is
no UI for this. If INVENTORY_DB_URL isn't set, the feature is silently a
no-op everywhere it's called, same as the optional CVE database upload.

Uses psycopg3 (not psycopg2) specifically because psycopg3 ships reliable
prebuilt wheels for modern Python / Apple Silicon, avoiding the "needs a C
compiler and libpq headers" failure mode psycopg2-binary can hit.
"""
import os
import re
from typing import List, Dict, Any, Optional

import psycopg
from psycopg import sql

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class InventoryError(Exception):
    pass


def is_configured() -> bool:
    return bool(os.environ.get("INVENTORY_DB_URL"))


def default_config() -> Optional[Dict[str, Any]]:
    """Builds the inventory config entirely from environment variables.
    Returns None if INVENTORY_DB_URL isn't set, so callers can just do
    `db_config = default_config()` and pass it straight through."""
    url = os.environ.get("INVENTORY_DB_URL")
    if not url:
        return None
    return {
        "url": url,
        "schema": os.environ.get("INVENTORY_DB_SCHEMA", ""),
        "table": os.environ.get("INVENTORY_DB_TABLE", "devices"),
    }


def _validate_identifier(name: str, kind: str):
    if not name or not IDENTIFIER_RE.match(name):
        raise InventoryError(
            f"Invalid {kind} name: {name!r}. Only letters, digits, and underscores are allowed."
        )


def _connect(cfg: Dict[str, Any]):
    url = cfg.get("url")
    if not url:
        raise InventoryError("No connection URL configured.")
    try:
        return psycopg.connect(url, connect_timeout=8)
    except Exception as e:
        raise InventoryError(f"Could not connect to Postgres: {e}")


def _table_identifier(cfg: Dict[str, Any], table: str):
    """Schema-qualified identifier when a schema is configured
    (e.g. "kasawie"."synthetic_network_inventory"), bare table otherwise."""
    schema = cfg.get("schema")
    if schema:
        _validate_identifier(schema, "schema")
        return sql.Identifier(schema, table)
    return sql.Identifier(table)


def test_connection(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Connectivity/sanity check -- not exposed via any endpoint or UI, but
    useful to call from a one-off script if you need to debug the connection."""
    table = cfg.get("table", "devices")
    _validate_identifier(table, "table")
    conn = _connect(cfg)
    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(_table_identifier(cfg, table)))
            count = cur.fetchone()[0]
        return {"ok": True, "row_count": count}
    finally:
        conn.close()


def fetch_all_devices(cfg: Dict[str, Any], max_rows: int = 20000) -> List[Dict[str, Any]]:
    """Pulls every row from the configured inventory table as a list of plain
    dicts, using whatever columns actually exist (via cursor.description --
    no assumptions about column names beyond the table itself). max_rows is
    a sanity ceiling, not a practical limit -- real fleets can run into the
    thousands, which is exactly why group_devices_by_signature below exists:
    that's what actually keeps the LLM prompt small, not this cap."""
    table = cfg.get("table", "devices")
    _validate_identifier(table, "table")
    conn = _connect(cfg)
    try:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("SELECT * FROM {} LIMIT %s").format(_table_identifier(cfg, table)),
                (max_rows,),
            )
            colnames = [d[0] for d in cur.description]
            rows = cur.fetchall()
    except Exception as e:
        raise InventoryError(f"Inventory query failed: {e}")
    finally:
        conn.close()
    return [dict(zip(colnames, row)) for row in rows]


# Column-name tokens that indicate a "product identity" field (what
# software/hardware a device runs) as opposed to an "instance identity" field
# (which specific device it is). Whole-word match only -- a loose substring
# check would (and did, during earlier testing) wrongly match "os" inside
# "hostname", fragmenting every device into its own group of one.
SIGNATURE_COLUMN_HINTS = ("vendor", "product", "model", "firmware", "version", "os", "platform", "device_type", "type")


def _is_signature_column(col: str) -> bool:
    tokens = re.split(r"[^a-z0-9]+", col.lower())
    return any(hint in tokens for hint in SIGNATURE_COLUMN_HINTS)


def group_devices_by_signature(devices: List[Dict[str, Any]], max_groups: int = 300) -> List[Dict[str, Any]]:
    """Groups devices by their product-identity columns (vendor/model/firmware/
    etc., auto-detected by column name), so a prompt can reason about product
    SIGNATURES rather than every individual device. Each returned group has
    the signature fields, a count, and a few representative devices. This is
    the single biggest lever for keeping the exposure-scan prompt small
    regardless of fleet size -- 4,500 devices might only be ~50 distinct
    signatures (confirmed against a real 4,500-row inventory during testing:
    the naive per-device approach would have needed ~360,000 tokens in one
    call; grouping brought that down to ~1,700)."""
    if not devices:
        return []
    all_cols = list(devices[0].keys())
    signature_cols = [c for c in all_cols if _is_signature_column(c)]
    if not signature_cols:
        signature_cols = all_cols  # nothing matched -- fall back rather than crash

    ip_like = next((c for c in all_cols if c.lower() in ("ip", "ip_address", "device_ip")), None)
    name_like = next((c for c in all_cols if c.lower() in ("hostname", "host_name", "name", "device_name")), None)

    groups: "Dict[tuple, Dict[str, Any]]" = {}
    for d in devices:
        key = tuple(d.get(c) for c in signature_cols)
        if key not in groups:
            groups[key] = {"signature": dict(zip(signature_cols, key)), "count": 0, "sample_devices": []}
        g = groups[key]
        g["count"] += 1
        if len(g["sample_devices"]) < 5:
            g["sample_devices"].append({
                "ip": d.get(ip_like) if ip_like else None,
                "name": d.get(name_like) if name_like else None,
            })

    result = list(groups.values())
    result.sort(key=lambda g: g["count"], reverse=True)
    return result[:max_groups]
