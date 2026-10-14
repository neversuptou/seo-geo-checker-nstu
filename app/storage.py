from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _get_db_path() -> Path:
    db_dir = Path(__file__).resolve().parent.parent / "data"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "audits.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_get_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            result_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def save_audit(result: Dict[str, Any]) -> int:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audits (url, score, result_json) VALUES (?, ?, ?)",
        (result.get("url"), result.get("overall_score", 0), json.dumps(result, ensure_ascii=False)),
    )
    conn.commit()
    audit_id = cur.lastrowid
    conn.close()
    return int(audit_id)


def list_audits(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, url, score, created_at FROM audits ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_audit(id: int) -> Dict[str, Any] | None:
    init_db()
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, url, score, result_json, created_at FROM audits WHERE id = ?", (id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json"))
    return data
