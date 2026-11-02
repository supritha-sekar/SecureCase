# SecureCase — Secure Digital Document Management System

A **local educational prototype** implementing the core modules in the uploaded final-year project report, *Secure Digital Document Management System for Legal and Investigation Documents*.

## Implemented

- React/Vite dashboard, login, cases, document upload/search, version history, integrity check, roles, audit trail and backups
- Flask REST API, PostgreSQL through SQLAlchemy (SQLite alternative for first-run testing)
- Argon2 password hashing, server-side case authorization, signed HttpOnly session cookies, CSRF protection, 30-minute expiry, login lockout and request rate limits
- AES-256-GCM encrypted storage, random nonce per version, SHA-256 plaintext fingerprints and integrity verification
- Historical document versions, assigned-case permissions, timed document sharing, SHA-256 hash-chained audit records
- Watermark on downloaded PDFs, PNG/JPG and TXT files; encrypted database/document export backups
- Pytest security and workflow tests

## Important limitations (read before use)

**Not production-ready and not a certified forensic evidence platform.** Use fictional data only. A single-host database administrator could rewrite the entire audit chain; use externally anchored checkpoints and append-only external logs for stronger tamper evidence. The local backup export is not an automated restore system. DOCX and MP4 downloads are *not watermarked* (returned unchanged after integrity verification); use PDFs/images/TXT for the watermark demonstration. No malware scanner is bundled. Files are size/signature validated but not guaranteed safe. Authentication uses Flask signed cookie sessions, not server-revocable sessions; logout clears the browser cookie, but immediate server-side session revocation across stolen copies requires an additional server-side session store. Rate limiting is in-memory and resets on restart. HTTPS is not configured for localhost; deploy behind a properly configured TLS reverse proxy. PostgreSQL migrations are not bundled; `create_all()` initializes tables for a fresh demo database. Backup restoration is a manual procedure, and encryption keys are intentionally excluded from backup archives.

## Windows setup (PowerShell)

### 1. Backend

```powershell
cd backend
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Generate secure secrets (run each command separately):

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `backend/.env` and replace **SECRET_KEY** and **DOCUMENT_KEY** with **different** 64-character hex strings. Set **ADMIN_PASSWORD** to your own unique password of at least 12 characters. Do not share the `.env` file or commit it to Git.

### 2. PostgreSQL (recommended)

Install PostgreSQL, create a database named `sddms` and an application user with a strong password. Set `DATABASE_URL=postgresql+psycopg://sddms:YOUR_PASSWORD@localhost:5432/sddms` in `.env`.

For the quickest **local demo**, leave `DATABASE_URL=sqlite:///sddms.db`. SQLite is a local development alternative, not the PostgreSQL target from the report.

### 3. Start the backend

```powershell
python app.py
```

Flask runs at http://127.0.0.1:5000. On the first start it initializes tables and creates the initial administrator using the credentials in `.env`.

### 4. Frontend (second terminal)

```powershell
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173. Vite proxies `/api` to Flask.

### 5. Test

```powershell
cd backend
.venv\Scripts\Activate.ps1
python -m pytest -q
```

## Suggested demo

1. Log in as administrator using your `.env` credentials.
2. Create a case and a user with the Investigator role; assign the user to the case.
3. Upload a **fictional valid PDF**. See the SHA-256 fingerprint in the version details.
4. Verify document integrity, then download the watermarked PDF.
5. Upload a second version of the same format and confirm both versions remain listed.
6. Check the audit trail and run the chain verification.
7. Create a backup and confirm the ZIP was created under `backend/backups/`.
8. For a controlled tampering demo, alter a `.enc` file in `backend/storage/` and retry verification; it should fail.

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/csrf` | Initialize CSRF token |
| POST | `/api/login` | Authenticate |
| POST | `/api/logout` | End browser session |
| GET | `/api/me` | Current user |
| GET, POST | `/api/users` | Admin user management |
| PATCH | `/api/users/:id` | Update role / active state |
| GET, POST | `/api/cases` | List/create cases |
| PATCH | `/api/cases/:id` | Update case |
| POST | `/api/cases/:id/assign` | Assign user |
| GET | `/api/documents` | Search case documents |
| POST | `/api/cases/:id/documents` | Upload encrypted document |
| GET, PATCH | `/api/documents/:id` | Document metadata |
| POST | `/api/documents/:id/versions` | Upload new version |
| GET | `/api/documents/:id/verify` | Integrity check |
| GET | `/api/documents/:id/download` | Download authorized version |
| POST | `/api/documents/:id/share` | Time-limited sharing |
| GET | `/api/audit` | Audit records |
| GET | `/api/audit/verify` | Verify hash chain |
| POST | `/api/backups` | Export backup |

For mutating endpoints (except login), send `X-CSRF-Token` obtained from `/api/csrf` or `/api/login`, with cookies enabled.

## Report alignment and deviations

Chapter 5's core security and case-document modules are represented. The implementation uses Flask/React/PostgreSQL-compatible SQLAlchemy, which are among the report's permitted options. Role permissions follow the report's Table 5.1 with case-level restrictions. Unlike the appendix's illustrative in-memory dictionaries, this implementation persists metadata in a database and ciphertext on disk. The report's future enhancements (MFA, blockchain, AI/OCR, digital signatures) are not included.

## Security notes

- Protect and separately back up `DOCUMENT_KEY`: loss means permanent loss of encrypted documents.
- Do not upload real evidence or personal data to this prototype.
- Do not deploy Flask's development server publicly.
- Use TLS, a persistent session store, external log anchoring, migrations, malware scanning, hardened backup restore and a security audit before considering any operational use.
