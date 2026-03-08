# mrv

Backend + frontend bundle for Morv messenger/admin.

## Local run

```bash
npm start
```

App routes:

- Messenger: `http://localhost:3000/`
- Admin panel: `http://localhost:3000/admmrv`
- Healthcheck: `http://localhost:3000/healthz`

## Deploy to Render (ready)

This repository is now ready for Render deploy.

### Option 1 (recommended): Blueprint
1. Push repo to GitHub.
2. In Render, click **New +** → **Blueprint**.
3. Select this repo.
4. Render will use `render.yaml` automatically.
5. In service env vars set:
   - `MRV_ADMIN_LOGIN`
   - `MRV_ADMIN_PASSWORD`
6. Deploy.

### Option 2: Manual Web Service
- Environment: `Node`
- Build Command: `node -v`
- Start Command: `npm start`
- Health Check Path: `/healthz`

## Backend behavior (implemented)

- Real server creation endpoint (`POST /api/servers`) creates an empty server.
- Invites rotate/expire in 24h (`POST /api/servers/:serverId/invites/refresh`).
- Invite join endpoint (`POST /invite/:token/join`).
- Panic endpoint (`POST /api/panic`) removes user sessions/account/memberships/sent messages.
- Admin server-ban endpoint (`POST /api/admin/ban-server`) applies permanent user/IP bans for server participants.
- Messages are stored as encrypted payload fields (`ciphertext`, `nonce`, `epk`) only.
- Realtime channel available via SSE (`GET /api/events`) and voice signaling relay (`POST /api/voice/signal`).

## Environment variables

- `PORT` (default `3000`)
- `MRV_ADMIN_LOGIN` (default `admin`)
- `MRV_ADMIN_PASSWORD` (default `change-me-now`)
