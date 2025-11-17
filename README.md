# OpenVPN Server Dashboard

**English** | [Русский](README.ru.md)

Multi-server OpenVPN monitoring with web interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)

## Features

- Multi-server support
- Traffic charts (5min-7days)
- Real-time active sessions
- User statistics with search/sort
- CSV/JSON export
- Multiple simultaneous sessions per user
- Auto-cleanup

## Quick Start

```bash
git clone https://github.com/yourusername/openvpn-server-dashboard.git
cd openvpn-server-dashboard
mkdir -p data
make up
# Open http://localhost:80
```

## Configuration

Edit `docker-compose.yml`:

**Multiple servers:**
```yaml
environment:
  - SERVERS_CONFIG=server1:/path/status.log:/path/vpn.log;server2:/path/status.log
```

**Single server:**
```yaml
environment:
  - OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
```

### OpenVPN config
```
status /var/log/openvpn/openvpn-status.log
status-version 2
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UPDATE_INTERVAL` | 60 | Update interval (seconds) |
| `RETENTION_DAYS` | 90 | Session retention (days) |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | 30 | Chart data retention (days) |

## API

- `GET /api/health` - Health check
- `GET /api/servers` - Server list
- `GET /api/summary` - Summary stats
- `GET /api/active_sessions?server=NAME` - Active sessions
- `GET /api/user_stats?server=NAME&limit=50&search=user` - User stats
- `GET /api/traffic_chart?server=NAME&hours=24` - Traffic data
- `GET /api/export/sessions?format=csv` - Export sessions
- `GET /api/export/users?format=json` - Export users

## Database

SQLite database with 3 tables:
- `sessions` - VPN sessions
- `user_stats` - Aggregated user statistics
- `traffic_history` - Traffic deltas for charts

**Important:** Traffic stored as deltas, not accumulated values. Handles reconnections correctly.

## Makefile

```bash
make up        # Start
make down      # Stop
make restart   # Restart
make logs      # View logs
make clean     # Clean all data
```

## SSL (Optional)

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt
```

## License

MIT
