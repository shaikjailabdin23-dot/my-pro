# CyberShield AI

A defensive cybersecurity monitoring workspace with a React SOC dashboard and Express REST API. The default demo mode runs immediately with realistic data and a clear demo boundary. Analysis endpoints are non-destructive and intended only for systems the user owns or is authorized to assess.

## Run locally

```bash
npm install
npm run install:all
npm run dev
```

Open http://localhost:5173. Demo credentials: `analyst@cybershield.ai` / `demo`.

The API runs on http://localhost:4000. Copy `server/.env.example` to `server/.env` to configure the port, JWT secret, CORS origin, and future PostgreSQL connection. The relational schema is in `server/schema.sql`; the current demo store keeps the app usable without infrastructure setup, while the tables define the production persistence boundary.

## API surface

- `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`
- `GET /api/dashboard`, `/api/events`, `/api/alerts`, `/api/vulnerabilities`, `/api/audit-logs`
- `PATCH /api/alerts/:id`, `PATCH /api/vulnerabilities/:id`
- `POST /api/scans`, `/api/url-analysis`, `/api/ip-analysis`, `/api/log-analysis`
- `GET /api/reports`, `POST /api/reports`, `DELETE /api/reports/:id`

All application routes require a JWT. The API includes Helmet, CORS, rate limiting, structured validation for analysis inputs, request logging, and centralized error handling. Replace the demo store with parameterized PostgreSQL repository calls using the provided schema before production deployment.
