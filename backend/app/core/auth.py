"""Users, roles and sessions.

Three roles, each a superset of the next:
  * reader  — can browse the query history.
  * analyst — reader + run lookups (which also writes them to the history).
  * admin   — analyst + edit verdict weights and manage users.

Users and sessions live in backend/data/users.db (same Docker volume as the
history). Passwords are hashed with scrypt from the standard library. Sessions are
opaque random tokens sent as an HttpOnly cookie; only their SHA-256 is stored, so a
leaked database can't be replayed as live sessions. Sessions are server-side, which
lets a password reset, role change or deactivation take effect immediately.

API tokens (for scripts and integrations) are created by an admin for any user and
sent as `Authorization: Bearer ick_…`. A token acts as its user: it has the user's
current role, stops working when the user is disabled or deleted, and is stored
only as a SHA-256 hash — the full value is shown once, at creation.
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi import Depends, HTTPException, Request

from app.core import config  # noqa: F401 — loads backend/.env before the settings below are read

log = logging.getLogger("intelchecker.auth")

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "users.db"

ROLES = ("admin", "analyst", "reader")
PERMISSIONS: dict[str, set[str]] = {
    "admin": {"history:read", "analyze", "admin"},
    "analyst": {"history:read", "analyze"},
    "reader": {"history:read"},
}

COOKIE_NAME = "intelchecker_session"
SESSION_TTL_SECONDS = max(1, int(os.environ.get("SESSION_TTL_HOURS", "12") or 12)) * 3600
COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").strip().lower() in ("true", "1", "yes")

USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")
PASSWORD_MIN = 8
# First-start admin password when ADMIN_PASSWORD is unset. Shorter than PASSWORD_MIN
# on purpose: no user can set it again, so "still uses it" means "never changed it".
DEFAULT_ADMIN_PASSWORD = "admin"
PASSWORD_MAX = 256

# scrypt cost: ~16 MiB / ~50 ms per hash — fine for a login endpoint.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1


def api_error(status: int, code: str, message: str) -> HTTPException:
    """Errors carry a code so the frontend can translate them (i18n/errors.ts)."""
    return HTTPException(status_code=status, detail={"code": code, "message": message})


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p),
        )
        return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


# Verified against when the username doesn't exist, so a login attempt takes the
# same time whether or not the user is real.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise api_error(422, "InvalidUsername",
                        "Username must be 3–64 characters: letters, digits, '.', '_', '-' or '@'.")
    return username


def validate_password(password: str) -> str:
    if not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
        raise api_error(422, "WeakPassword", f"Password must be at least {PASSWORD_MIN} characters long.")
    return password


def validate_role(role: str) -> str:
    if role not in ROLES:
        raise api_error(422, "InvalidRole", f"Role must be one of: {', '.join(ROLES)}.")
    return role


# ── Storage ───────────────────────────────────────────────────────────────────

@contextmanager
def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


_USER_COLUMNS = "id, username, role, active, must_change_password, created_at, last_login"


def _public(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    user = {k: row[k] for k in ("id", "username", "role", "created_at", "last_login")}
    user["active"] = bool(row["active"])
    user["must_change_password"] = bool(row["must_change_password"])
    return user


def init_db() -> None:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used TEXT,
                expires_at TEXT
            )
        """)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            _bootstrap_admin(conn)


def _bootstrap_admin(conn: sqlite3.Connection) -> None:
    """First start: create the initial admin from ADMIN_USERNAME / ADMIN_PASSWORD,
    defaulting to admin / admin. The default password is not forced to change, but
    the UI warns while it is still in use (see uses_default_password). Never runs
    again once any user exists."""
    username = os.environ.get("ADMIN_USERNAME", "").strip() or "admin"
    password = os.environ.get("ADMIN_PASSWORD", "")
    default = not password
    if default:
        password = DEFAULT_ADMIN_PASSWORD
    elif len(password) < PASSWORD_MIN:
        raise RuntimeError(f"ADMIN_PASSWORD must be at least {PASSWORD_MIN} characters long.")
    conn.execute(
        "INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, 'admin', ?)",
        (username, hash_password(password), 0),
    )
    if default:
        log.warning(
            "No users found — created initial admin '%s' with the default password '%s'. "
            "Change it before going to production.", username, DEFAULT_ADMIN_PASSWORD,
        )
    else:
        log.warning("No users found — created initial admin '%s' from ADMIN_USERNAME/ADMIN_PASSWORD.", username)


def list_users() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(f"SELECT {_USER_COLUMNS} FROM users ORDER BY username COLLATE NOCASE").fetchall()
        counts = dict(conn.execute(
            "SELECT user_id, COUNT(*) FROM api_tokens "
            "WHERE expires_at IS NULL OR expires_at > datetime('now') GROUP BY user_id"
        ).fetchall())
        return [{**_public(r), "api_tokens": counts.get(r["id"], 0)} for r in rows]


# ── API tokens ────────────────────────────────────────────────────────────────

API_TOKEN_PREFIX = "ick_"
TOKEN_NAME_MAX = 64
TOKEN_MAX_DAYS = 3650
_TOKEN_COLUMNS = "id, name, prefix, created_at, last_used, expires_at"


def _token_public(row: sqlite3.Row) -> dict:
    token = {k: row[k] for k in ("id", "name", "prefix", "created_at", "last_used", "expires_at")}
    token["expired"] = bool(row["expired"])
    return token


def list_tokens(user_id: int) -> list[dict]:
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
            raise api_error(404, "UserNotFound", "User not found.")
        rows = conn.execute(
            f"SELECT {_TOKEN_COLUMNS}, (expires_at IS NOT NULL AND expires_at <= datetime('now')) AS expired "
            "FROM api_tokens WHERE user_id = ? ORDER BY id DESC", (user_id,),
        ).fetchall()
        return [_token_public(r) for r in rows]


def create_token(user_id: int, name: str, expires_in_days: int | None) -> tuple[str, dict]:
    """Returns (raw token — shown once, never stored —, token metadata)."""
    name = name.strip()
    if not (1 <= len(name) <= TOKEN_NAME_MAX):
        raise api_error(422, "InvalidTokenName", f"Token name must be 1–{TOKEN_NAME_MAX} characters.")
    if expires_in_days is not None and not (1 <= expires_in_days <= TOKEN_MAX_DAYS):
        raise api_error(422, "InvalidTokenExpiry", f"Expiry must be between 1 and {TOKEN_MAX_DAYS} days.")
    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
            raise api_error(404, "UserNotFound", "User not found.")
        cur = conn.execute(
            "INSERT INTO api_tokens (user_id, name, token_hash, prefix, expires_at) VALUES (?, ?, ?, ?, "
            "CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', '+' || ? || ' days') END)",
            (user_id, name, _token_hash(raw), raw[:len(API_TOKEN_PREFIX) + 6], expires_in_days, expires_in_days),
        )
        row = conn.execute(
            f"SELECT {_TOKEN_COLUMNS}, 0 AS expired FROM api_tokens WHERE id = ?", (cur.lastrowid,),
        ).fetchone()
        return raw, _token_public(row)


def delete_token(user_id: int, token_id: int) -> None:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM api_tokens WHERE id = ? AND user_id = ?", (token_id, user_id))
        if cur.rowcount == 0:
            raise api_error(404, "TokenNotFound", "API token not found.")


def _user_for_api_token(raw: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT t.id AS token_id, {', '.join('u.' + c.strip() for c in _USER_COLUMNS.split(','))} "
            "FROM api_tokens t JOIN users u ON u.id = t.user_id "
            "WHERE t.token_hash = ? AND u.active = 1 "
            "AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))",
            (_token_hash(raw),),
        ).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE api_tokens SET last_used = datetime('now') WHERE id = ?", (row["token_id"],))
        return _public(row)


def get_user(user_id: int) -> dict | None:
    with _connect() as conn:
        return _public(conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone())


def create_user(username: str, password: str, role: str) -> dict:
    username = validate_username(username)
    validate_password(password)
    validate_role(role)
    with _connect() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)",
                (username, hash_password(password), role),
            )
        except sqlite3.IntegrityError:
            raise api_error(409, "UserExists", f"A user named '{username}' already exists.")
        return _public(conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (cur.lastrowid,)).fetchone())


def _active_admins(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]


def update_user(user_id: int, acting_user_id: int, *, role: str | None = None,
                active: bool | None = None, password: str | None = None) -> dict:
    if role is not None:
        validate_role(role)
    if password is not None:
        validate_password(password)
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise api_error(404, "UserNotFound", "User not found.")
        if user_id == acting_user_id and ((role is not None and role != row["role"]) or active is False):
            raise api_error(409, "CannotModifySelf",
                            "You can't change your own role or deactivate yourself.")
        loses_admin = row["role"] == "admin" and row["active"] and (
            (role is not None and role != "admin") or active is False
        )
        if loses_admin and _active_admins(conn) <= 1:
            raise api_error(409, "LastAdmin", "There must always be at least one active admin.")

        if role is not None:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if active is not None:
            conn.execute("UPDATE users SET active = ? WHERE id = ?", (int(active), user_id))
        if password is not None:
            # An admin-set password is temporary: the user picks their own on next login.
            conn.execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                         (hash_password(password), user_id))
        if active is False or password is not None:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        return _public(conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (user_id,)).fetchone())


def delete_user(user_id: int, acting_user_id: int) -> None:
    with _connect() as conn:
        row = conn.execute("SELECT role, active FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise api_error(404, "UserNotFound", "User not found.")
        if user_id == acting_user_id:
            raise api_error(409, "CannotModifySelf", "You can't delete your own account.")
        if row["role"] == "admin" and row["active"] and _active_admins(conn) <= 1:
            raise api_error(409, "LastAdmin", "There must always be at least one active admin.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def change_own_password(user_id: int, current: str, new: str, keep_token_hash: str) -> None:
    validate_password(new)
    with _connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or not verify_password(current, row["password_hash"]):
            raise api_error(403, "WrongPassword", "The current password is incorrect.")
        if hmac.compare_digest(current, new):
            raise api_error(422, "SamePassword", "The new password must be different from the current one.")
        conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                     (hash_password(new), user_id))
        # Sign out every other session of this user; keep the one making the change.
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, keep_token_hash))


# ── Login throttling ──────────────────────────────────────────────────────────
# Per username, in memory: after _MAX_FAILURES failed logins within _WINDOW the
# account rejects further attempts until the window passes. Keyed by username
# rather than IP because behind the nginx proxy every request comes from the same
# address.

_MAX_FAILURES = 5
_WINDOW = 15 * 60
_failures: dict[str, list[float]] = {}
_failures_lock = threading.Lock()


def _recent_failures(key: str, now: float) -> list[float]:
    recent = [t for t in _failures.get(key, []) if now - t < _WINDOW]
    if recent:
        _failures[key] = recent
    else:
        _failures.pop(key, None)
    return recent


def login(username: str, password: str) -> tuple[str, dict]:
    """Returns (raw session token, user). Raises on bad credentials."""
    key = username.strip().lower()
    now = time.time()
    with _failures_lock:
        if len(_recent_failures(key, now)) >= _MAX_FAILURES:
            raise api_error(429, "TooManyAttempts",
                            "Too many failed sign-in attempts. Try again in a few minutes.")

    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
        ok = verify_password(password, row["password_hash"] if row else _DUMMY_HASH) and row is not None
        if not ok or not row["active"]:
            with _failures_lock:
                _failures.setdefault(key, []).append(now)
            # Same message for unknown user, wrong password and disabled account.
            raise api_error(401, "InvalidCredentials", "Invalid username or password.")

        with _failures_lock:
            _failures.pop(key, None)
        token = secrets.token_urlsafe(32)
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (int(now),))
        conn.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                     (_token_hash(token), row["id"], int(now) + SESSION_TTL_SECONDS))
        conn.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (row["id"],))
        return token, _public(conn.execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?", (row["id"],)).fetchone())


def uses_default_password(user_id: int) -> bool:
    """True while the account still has DEFAULT_ADMIN_PASSWORD (the UI shows a warning).
    One scrypt verification, only run on /auth/me, login and password change."""
    with _connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    return row is not None and verify_password(DEFAULT_ADMIN_PASSWORD, row["password_hash"])


def logout(token: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user_for_token(token: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f"SELECT {', '.join('u.' + c.strip() for c in _USER_COLUMNS.split(','))} "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ? AND s.expires_at >= ? AND u.active = 1",
            (_token_hash(token), int(time.time())),
        ).fetchone()
        return _public(row)


# ── FastAPI dependencies ──────────────────────────────────────────────────────

def session_user(request: Request) -> dict:
    """Authenticated user — by API token (Authorization: Bearer) or session cookie —,
    even one who still has to change their password. `user["auth"]` says which."""
    header = request.headers.get("authorization", "")
    scheme, _, credential = header.partition(" ")
    if scheme.lower() == "bearer" and credential.strip():
        user = _user_for_api_token(credential.strip())
        if user is None:
            raise api_error(401, "InvalidToken", "Invalid, expired or revoked API token.")
        user["auth"] = "token"
        return user

    token = request.cookies.get(COOKIE_NAME)
    user = _user_for_token(token) if token else None
    if user is None:
        raise api_error(401, "NotAuthenticated", "Sign in to continue.")
    user["auth"] = "session"
    user["token_hash"] = _token_hash(token)
    return user


def browser_session_user(user: dict = Depends(session_user)) -> dict:
    """Account actions (changing the password) need the interactive session, not a token."""
    if user["auth"] != "session":
        raise api_error(403, "SessionRequired", "This action requires signing in, not an API token.")
    return user


def current_user(user: dict = Depends(session_user)) -> dict:
    """Signed-in user allowed to use the app (temporary password already replaced).
    A temporary password only gates the interactive UI: API tokens are issued by an
    admin and keep working."""
    if user["must_change_password"] and user["auth"] == "session":
        raise api_error(403, "PasswordChangeRequired", "You must change your password before continuing.")
    return user


def require(permission: str):
    def dependency(user: dict = Depends(current_user)) -> dict:
        if permission not in PERMISSIONS.get(user["role"], set()):
            raise api_error(403, "Forbidden", "Your role doesn't allow this action.")
        return user
    return dependency
