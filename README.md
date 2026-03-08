# mrv

Node.js backend for Morv messenger/admin bundle.

## Run

```bash
npm start
```

Default app routes:

- Messenger: `http://localhost:3000/`
- Admin panel: `http://localhost:3000/admmrv`

## Security-relevant backend behavior

- Real server creation endpoint (`POST /api/servers`) creates an empty new server.
- Invite links are real and expire every 24h (`POST /api/servers/:serverId/invites/refresh`). QR endpoint is exposed via `GET /api/invites/:inviteToken/qr` (SVG payload for direct frontend rendering).
- Panic endpoint (`POST /api/panic`) clears user sessions, memberships, sent ciphertext messages, and account.
- Server ban from admin endpoint (`POST /api/admin/ban-server`) applies permanent IP/user ban for all current participants with reason support.
- Message API accepts only encrypted payload fields (`ciphertext`, `nonce`, `epk`) and stores ciphertext only.
- Server-Sent Events (`GET /api/events`) provide real-time events. Voice signaling is relayed through `POST /api/voice/signal` in real time to subscribed clients.

Environment variables:

- `PORT` (default `3000`)
- `MRV_ADMIN_LOGIN` (default `admin`)
- `MRV_ADMIN_PASSWORD` (default `change-me-now`)
