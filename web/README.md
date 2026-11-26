# web/ - the pages users see

Plain HTML and CSS, served by `src/api.py`. `theme.css` is shared by every page.

| File | Page | Address |
|---|---|---|
| `login.html` | Sign in, create account, forgot password, Google button | `/login.html` |
| `reset.html` | Choose a new password (opened from the email link) | `/reset.html?token=...` |
| `home.html` | Home: where to start | `/home` |
| `servers.html` | Connect a server and get its token | `/servers` |
| `threat_center.html` | Live traffic, attacks, incident review | `/threat-center` |
| `server_ai.html` | Budget and protection plan | `/server-ai` |
| `index.html` | Dashboard | `/dashboard` |
| `risk_overview.html` | Asset risk overview | `/portfolio` |
| `detections.html` | Offline intrusion benchmark results | `/detections` |
| `settings.html` | Password, login limit, email and Google linking | `/settings` |
| `theme.css` | Colours, fonts, shared styles | - |
