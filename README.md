# Ninjutsu Master

The repository contains the downloaded static frontend and an independent API service.

## Run locally

```bash
npm install
npm start
```

The site and API are served at `http://localhost:8787`. Set `DATABASE_PATH` to keep the SQLite database outside the repository, and set `COOKIE_SECURE=true` when serving over HTTPS.

## API foundation

- `GET /api/health`
- `POST /api/auth/register` with `{ "email", "password" }`
- `POST /api/auth/login` with `{ "email", "password" }`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/entities/:type`
- `POST/PATCH/DELETE /api/entities/:type[/:id]` for staff users

Passwords are hashed with bcrypt. Sessions are stored server-side as SHA-256 hashes and sent in an HTTP-only cookie. Helmet, CORS, JSON size limits, input validation, rate limiting, SQLite foreign keys, and WAL mode are enabled by default.

The downloaded frontend still contains the original Base44 client inside its compiled bundle. The new API is intentionally kept separate until that client layer is replaced and each public/admin workflow can be tested against the local database.
