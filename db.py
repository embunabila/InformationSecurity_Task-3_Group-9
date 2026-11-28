import sqlite3
from pathlib import Path
from datetime import datetime, timezone


DB_PATH = Path(__file__).resolve().parent / "medimo.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_connection()

    try:
        connection.executescript("""
            -- =========================================
            -- TASK 1: EXISTING TABLES
            -- =========================================

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE
                    CHECK (length(trim(username)) > 0),
                password_hash TEXT NOT NULL
                    CHECK (length(trim(password_hash)) > 0)
            );

            CREATE TABLE IF NOT EXISTS health_profiles (
                user_id INTEGER PRIMARY KEY,
                aes_envelope BLOB NOT NULL,
                des_envelope BLOB NOT NULL,
                rc4_envelope BLOB NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS medical_files (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                category TEXT NOT NULL
                    CHECK (
                        category IN ('identity', 'document', 'video')
                    ),
                aes_storage_name TEXT NOT NULL UNIQUE,
                des_storage_name TEXT NOT NULL UNIQUE,
                rc4_storage_name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            -- =========================================
            -- TASK 2: USER KEYS
            -- =========================================

            CREATE TABLE IF NOT EXISTS user_keys (
                user_id INTEGER PRIMARY KEY,

                public_key_pem TEXT NOT NULL
                    CHECK (length(trim(public_key_pem)) > 0),

                private_key_salt BLOB NOT NULL
                    CHECK (length(private_key_salt) = 16),

                encrypted_private_key BLOB NOT NULL
                    CHECK (length(encrypted_private_key) > 0),

                fingerprint TEXT NOT NULL UNIQUE
                    CHECK (length(trim(fingerprint)) > 0),

                failed_unlock_count INTEGER NOT NULL DEFAULT 0
                    CHECK (failed_unlock_count >= 0),

                locked_until TEXT,

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            -- =========================================
            -- TASK 2: SHARE REQUESTS
            -- =========================================

            CREATE TABLE IF NOT EXISTS share_requests (
                id TEXT PRIMARY KEY,

                requester_id INTEGER NOT NULL,
                owner_id INTEGER NOT NULL,

                category TEXT NOT NULL
                    CHECK (
                        category IN (
                            'profile',
                            'identity',
                            'document',
                            'video'
                        )
                    ),

                reason TEXT NOT NULL
                    CHECK (
                        length(trim(reason)) > 0
                        AND length(reason) <= 500
                    ),

                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (
                        status IN (
                            'pending',
                            'approved',
                            'rejected',
                            'revoked',
                            'expired'
                        )
                    ),

                wrapped_key BLOB,

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                -- NULL while pending; set when the owner approves.
                -- Format: 'YYYY-MM-DD HH:MM:SS' in Asia/Jakarta time.
                expires_at TEXT
                    CHECK (
                        expires_at IS NULL
                        OR (
                            length(expires_at) = 19
                            AND expires_at GLOB
                            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]'
                        )
                    ),

                decided_at TEXT,

                CHECK (requester_id <> owner_id),

                FOREIGN KEY (requester_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            -- =========================================
            -- TASK 2: SHARED ITEMS
            -- =========================================

            CREATE TABLE IF NOT EXISTS shared_items (
                id TEXT PRIMARY KEY,

                request_id TEXT NOT NULL,

                source_file_id TEXT,

                category TEXT NOT NULL
                    CHECK (
                        category IN (
                            'profile',
                            'identity',
                            'document',
                            'video'
                        )
                    ),

                storage_name TEXT NOT NULL UNIQUE
                    CHECK (length(trim(storage_name)) > 0),

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (request_id)
                    REFERENCES share_requests(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (source_file_id)
                    REFERENCES medical_files(id)
                    ON DELETE SET NULL
            );


            -- =========================================
            -- TASK 2: SHARE AUDIT LOG
            -- =========================================

            CREATE TABLE IF NOT EXISTS share_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                request_id TEXT,

                actor_id INTEGER,

                action TEXT NOT NULL
                    CHECK (length(trim(action)) > 0),

                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (request_id)
                    REFERENCES share_requests(id)
                    ON DELETE SET NULL,

                FOREIGN KEY (actor_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            );


            -- =========================================
            -- TASK 3: SIGNING KEYS
            -- =========================================

            CREATE TABLE IF NOT EXISTS signing_keys (
                user_id INTEGER PRIMARY KEY,
                public_key_pem TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                certificate_der BLOB NOT NULL,
                private_key_salt BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                failed_unlock_count INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,

                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            -- =========================================
            -- TASK 3: DOCUMENT SIGNATURES
            -- =========================================

            CREATE TABLE IF NOT EXISTS document_signatures (
                id TEXT PRIMARY KEY,
                signed_file_id TEXT NOT NULL UNIQUE,
                source_file_id TEXT,
                signer_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                document_digest TEXT NOT NULL,
                signed_at TEXT NOT NULL,

                FOREIGN KEY (signed_file_id)
                    REFERENCES medical_files(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (source_file_id)
                    REFERENCES medical_files(id)
                    ON DELETE SET NULL,

                FOREIGN KEY (signer_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            );


            -- =========================================
            -- TASK 3: SIGNATURE AUDIT LOG
            -- =========================================

            CREATE TABLE IF NOT EXISTS signature_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                file_id TEXT,
                action TEXT NOT NULL
                    CHECK (
                        action IN (
                            'key_generated',
                            'signed',
                            'verified',
                            'verify_failed'
                        )
                    ),
                created_at TEXT NOT NULL,

                FOREIGN KEY (actor_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            );


            -- =========================================
            -- INDEXES: TASK 1
            -- =========================================

            CREATE INDEX IF NOT EXISTS idx_medical_files_owner
                ON medical_files(owner_id);

            CREATE INDEX IF NOT EXISTS idx_medical_files_owner_created
                ON medical_files(owner_id, created_at);


            -- =========================================
            -- INDEXES: TASK 2
            -- =========================================

            CREATE INDEX IF NOT EXISTS idx_share_requests_requester
                ON share_requests(requester_id);

            -- At most one pending request per requester/owner pair.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_share_requests_one_pending
                ON share_requests(requester_id, owner_id)
                WHERE status = 'pending';

            CREATE INDEX IF NOT EXISTS idx_share_requests_owner_status
                ON share_requests(owner_id, status);

            CREATE INDEX IF NOT EXISTS idx_share_requests_expires
                ON share_requests(status, expires_at);

            CREATE INDEX IF NOT EXISTS idx_shared_items_request
                ON shared_items(request_id);

            CREATE INDEX IF NOT EXISTS idx_share_audit_request
                ON share_audit_log(request_id);

        """)
    finally:
        connection.close()


# =============================================
# TASK 1: USER FUNCTIONS
# =============================================

def create_user(username, password_hash):
    connection = get_connection()

    try:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        connection.commit()
    finally:
        connection.close()


def get_user_by_username(username):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        connection.close()


def get_user_by_id(user_id):
    connection = get_connection()

    try:
        return connection.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    finally:
        connection.close()


# =============================================
# TASK 1: HEALTH PROFILE FUNCTIONS
# =============================================

def save_health_profile(user_id, aes_envelope, des_envelope, rc4_envelope):
    envelopes = (aes_envelope, des_envelope, rc4_envelope)

    if not all(isinstance(envelope, bytes) for envelope in envelopes):
        raise TypeError("Semua envelope profil harus berupa bytes.")

    connection = get_connection()

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO health_profiles (
                    user_id,
                    aes_envelope,
                    des_envelope,
                    rc4_envelope
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    aes_envelope = excluded.aes_envelope,
                    des_envelope = excluded.des_envelope,
                    rc4_envelope = excluded.rc4_envelope,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (user_id, aes_envelope, des_envelope, rc4_envelope),
            )
    finally:
        connection.close()


def get_health_profile_envelopes(user_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT aes_envelope, des_envelope, rc4_envelope, updated_at
            FROM health_profiles
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
    finally:
        connection.close()


# =============================================
# TASK 1: MEDICAL FILE FUNCTIONS
# =============================================

def create_medical_file(
    file_id,
    owner_id,
    category,
    aes_storage_name,
    des_storage_name,
    rc4_storage_name,
):
    if category not in {"identity", "document", "video"}:
        raise ValueError("Kategori berkas tidak valid.")

    storage_names = (
        aes_storage_name,
        des_storage_name,
        rc4_storage_name,
    )

    if not all(
        isinstance(name, str) and name.strip()
        for name in storage_names
    ):
        raise ValueError("Nama penyimpanan berkas tidak valid.")

    if len(set(storage_names)) != 3:
        raise ValueError("Setiap cipher harus memiliki nama file berbeda.")

    connection = get_connection()

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO medical_files (
                    id,
                    owner_id,
                    category,
                    aes_storage_name,
                    des_storage_name,
                    rc4_storage_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    owner_id,
                    category,
                    aes_storage_name,
                    des_storage_name,
                    rc4_storage_name,
                ),
            )
    finally:
        connection.close()


def get_medical_file(file_id, owner_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                id,
                owner_id,
                category,
                aes_storage_name,
                des_storage_name,
                rc4_storage_name,
                created_at
            FROM medical_files
            WHERE id = ? AND owner_id = ?
            """,
            (file_id, owner_id),
        ).fetchone()
    finally:
        connection.close()


def get_medical_files_for_owner(owner_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                id,
                category,
                created_at
            FROM medical_files
            WHERE owner_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (owner_id,),
        ).fetchall()
    finally:
        connection.close()


def delete_medical_file_record(file_id, owner_id):
    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                """
                DELETE FROM medical_files
                WHERE id = ? AND owner_id = ?
                """,
                (file_id, owner_id),
            )
            return cursor.rowcount == 1
    finally:
        connection.close()
# =============================================
# TASK 3: SIGNATURE DATABASE FUNCTIONS
# =============================================

def record_signature_event(actor_id, file_id, action):
    allowed_actions = {
        "key_generated",
        "signed",
        "verified",
        "verify_failed",
    }

    if action not in allowed_actions:
        raise ValueError("Signature audit action tidak valid.")

    created_at = datetime.now(timezone.utc).isoformat()

    connection = get_connection()

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO signature_audit_log (
                    actor_id,
                    file_id,
                    action,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (actor_id, file_id, action, created_at),
            )
    finally:
        connection.close()


def get_signature_record(file_id, owner_id):
    connection = get_connection()

    try:
        return connection.execute(
            """
            SELECT
                ds.id,
                ds.signed_file_id,
                ds.source_file_id,
                ds.signer_id,
                ds.fingerprint,
                ds.document_digest,
                ds.signed_at
            FROM document_signatures AS ds
            JOIN medical_files AS mf
                ON ds.signed_file_id = mf.id
            WHERE ds.signed_file_id = ?
                AND mf.owner_id = ?
            """,
            (file_id, owner_id),
        ).fetchone()
    finally:
        connection.close()


def get_signed_file_ids_for_owner(owner_id):
    """Return the set of the owner's medical_files ids that are signed copies."""
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT ds.signed_file_id
            FROM document_signatures AS ds
            JOIN medical_files AS mf
                ON ds.signed_file_id = mf.id
            WHERE mf.owner_id = ?
            """,
            (owner_id,),
        ).fetchall()
    finally:
        connection.close()

    return {row["signed_file_id"] for row in rows}

# =============================================
# DATABASE INITIALIZATION
# =============================================

if __name__ == "__main__":
    init_db()
    print(f"Database siap: {DB_PATH}")