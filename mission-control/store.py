"""SQLite store: crew provisioned by Entra ID (SCIM), the command queue, agents seen on the
agent API, pending sign-ins, and the activity log."""
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

COLUMNS = ("user_name", "external_id", "active", "display_name", "given_name",
           "family_name", "email", "title", "department")


class Conflict(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, path="missioncontrol.db"):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                user_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                external_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                display_name TEXT, given_name TEXT, family_name TEXT,
                email TEXT, title TEXT, department TEXT,
                created TEXT NOT NULL, last_modified TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, action TEXT NOT NULL, user_name TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL, action TEXT NOT NULL, rationale TEXT,
                proposed_by TEXT NOT NULL, proposer_type TEXT NOT NULL DEFAULT 'human',
                state TEXT NOT NULL DEFAULT 'Awaiting Flight Director',
                decided_by TEXT, decided_at TEXT, created TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS agents (
                object_id TEXT PRIMARY KEY,
                app_id TEXT, name TEXT, roles TEXT, last_seen TEXT);
            CREATE TABLE IF NOT EXISTS auth_flows (
                state TEXT PRIMARY KEY, browser_id TEXT NOT NULL, flow TEXT NOT NULL, created REAL NOT NULL);
        """)
        if not self._db.execute("SELECT 1 FROM commands LIMIT 1").fetchone():
            for cid, target, action, who in (
                    ("CMD-311", "MO-3 Petrel", "Exit safe mode, resume payload ops", "Angela Russo"),
                    ("CMD-312", "MO-2 Wren", "Station-keeping burn, +0.4 m/s", "Patrick Doyle")):
                self._db.execute("INSERT INTO commands (id, target, action, proposed_by, created) VALUES (?, ?, ?, ?, ?)",
                                 (cid, target, action, who, _now()))
        self._db.commit()

    # --- reads -----------------------------------------------------------
    def get(self, user_id):
        row = self._db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def find(self, column, value):
        if column not in ("id", "user_name", "external_id"):
            raise ValueError(column)
        collate = " COLLATE NOCASE" if column == "user_name" else ""
        rows = self._db.execute(f"SELECT * FROM users WHERE {column} = ?{collate}", (value,)).fetchall()
        return [dict(r) for r in rows]

    def by_user_name(self, user_name):
        found = self.find("user_name", user_name)
        return found[0] if found else None

    def all(self):
        rows = self._db.execute("SELECT * FROM users ORDER BY department, family_name, given_name").fetchall()
        return [dict(r) for r in rows]

    def events(self, limit=25, prefix=None, actions=None):
        if prefix:
            rows = self._db.execute("SELECT * FROM events WHERE action LIKE ? ORDER BY seq DESC LIMIT ?",
                                    (prefix + "%", limit)).fetchall()
        elif actions:
            marks = ", ".join("?" for _ in actions)
            rows = self._db.execute(f"SELECT * FROM events WHERE action IN ({marks}) ORDER BY seq DESC LIMIT ?",
                                    (*actions, limit)).fetchall()
        else:
            rows = self._db.execute("SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # --- command queue -----------------------------------------------------
    def commands(self):
        rows = self._db.execute("SELECT * FROM commands ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def command(self, command_id):
        row = self._db.execute("SELECT * FROM commands WHERE id = ?", (command_id,)).fetchone()
        return dict(row) if row else None

    def propose(self, target, action, rationale, proposed_by, proposer_type):
        with self._lock:
            numbers = [int(r["id"].split("-")[1]) for r in self._db.execute("SELECT id FROM commands").fetchall()]
            command_id = f"CMD-{max(numbers + [310]) + 1}"
            self._db.execute(
                "INSERT INTO commands (id, target, action, rationale, proposed_by, proposer_type, created) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", (command_id, target, action, rationale, proposed_by, proposer_type, _now()))
            self._db.commit()
        return self.command(command_id)

    def decide(self, command_id, approved, decided_by):
        with self._lock:
            state = "Approved" if approved else "Rejected"
            cur = self._db.execute(
                "UPDATE commands SET state = ?, decided_by = ?, decided_at = ? "
                "WHERE id = ? AND state = 'Awaiting Flight Director'", (state, decided_by, _now(), command_id))
            self._db.commit()
            return cur.rowcount == 1

    # --- agents seen on the agent API ------------------------------------
    def agent_seen(self, object_id, app_id, name, roles):
        with self._lock:
            self._db.execute(
                "INSERT INTO agents (object_id, app_id, name, roles, last_seen) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(object_id) DO UPDATE SET app_id = excluded.app_id, name = excluded.name, "
                "roles = excluded.roles, last_seen = excluded.last_seen",
                (object_id, app_id, name, json.dumps(sorted(roles)), _now()))
            self._db.commit()

    def agents_seen(self):
        rows = self._db.execute("SELECT * FROM agents ORDER BY name").fetchall()
        result = []
        for r in rows:
            item = dict(r)
            item["roles"] = json.loads(item["roles"] or "[]")
            result.append(item)
        return result

    # --- pending sign-ins (survive restarts; bound to one browser) --------
    def save_flow(self, state, browser_id, flow, max_age=900):
        with self._lock:
            self._db.execute("DELETE FROM auth_flows WHERE created < ?", (time.time() - max_age,))
            self._db.execute("INSERT OR REPLACE INTO auth_flows (state, browser_id, flow, created) VALUES (?, ?, ?, ?)",
                             (state, browser_id, json.dumps(flow), time.time()))
            self._db.commit()

    def take_flow(self, state, max_age=900):
        """Returns (browser_id, flow) and deletes it, so each sign-in can be completed once."""
        with self._lock:
            row = self._db.execute("SELECT * FROM auth_flows WHERE state = ?", (state,)).fetchone()
            if not row:
                return None
            self._db.execute("DELETE FROM auth_flows WHERE state = ?", (state,))
            self._db.commit()
        if time.time() - row["created"] > max_age:
            return None
        return row["browser_id"], json.loads(row["flow"])

    # --- writes ----------------------------------------------------------
    def create(self, fields):
        with self._lock:
            if self.by_user_name(fields["user_name"]):
                raise Conflict(fields["user_name"])
            user_id, now = str(uuid.uuid4()), _now()
            record = {c: fields.get(c) for c in COLUMNS}
            record["active"] = 1 if fields.get("active", True) else 0
            self._db.execute(
                f"INSERT INTO users (id, {', '.join(COLUMNS)}, created, last_modified) "
                f"VALUES (?, {', '.join('?' for _ in COLUMNS)}, ?, ?)",
                (user_id, *[record[c] for c in COLUMNS], now, now))
            self._db.commit()
            return self.get(user_id)

    def update(self, user_id, fields):
        fields = {k: v for k, v in fields.items() if k in COLUMNS}
        with self._lock:
            if "user_name" in fields:
                clash = self.by_user_name(fields["user_name"])
                if clash and clash["id"] != user_id:
                    raise Conflict(fields["user_name"])
            if "active" in fields:
                fields["active"] = 1 if fields["active"] else 0
            if fields:
                sets = ", ".join(f"{k} = ?" for k in fields)
                self._db.execute(f"UPDATE users SET {sets}, last_modified = ? WHERE id = ?",
                                 (*fields.values(), _now(), user_id))
                self._db.commit()
            return self.get(user_id)

    def delete(self, user_id):
        with self._lock:
            self._db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            self._db.commit()

    def log(self, action, user_name, detail=""):
        with self._lock:
            self._db.execute("INSERT INTO events (ts, action, user_name, detail) VALUES (?, ?, ?, ?)",
                             (_now(), action, user_name, detail))
            self._db.commit()
