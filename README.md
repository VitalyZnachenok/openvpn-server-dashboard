# OpenVPN Server Dashboard

**English** | [Русский](README.ru.md)

Multi-server OpenVPN monitoring with web interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)

## Features

- 🔐 **Token-based authentication**
- Multi-server support
- Traffic charts (5min-7days)
- Real-time active sessions
- User statistics with search/sort
- 📊 **User traffic comparison** (up to 10 users on one chart)
- 📋 **Session details viewer** (active and recent sessions per user)
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

## Authentication

The dashboard supports token-based authentication for secure access.

### Setting up authentication token

**Method 1: Using docker-compose.yml (recommended)**

```yaml
environment:
  - AUTH_ENABLED=true
  - AUTH_TOKEN=your-secret-token-here
```

**Method 2: Generate secure token**

```bash
# Generate random secure token
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Example output: xJ8kP2mN5qR9sT4vW7yZ0aB3cD6eF1gH

# Add to docker-compose.yml:
- AUTH_TOKEN=xJ8kP2mN5qR9sT4vW7yZ0aB3cD6eF1gH
```

**Method 3: Disable authentication (not recommended)**

```yaml
environment:
  - AUTH_ENABLED=false
```

### First login

1. Start the dashboard: `make up`
2. Check logs for auto-generated token (if AUTH_TOKEN not set):
   ```bash
   make logs | grep "Generated random token"
   ```
3. Open http://localhost:80
4. Enter your token on the login page
5. Token will be saved in browser localStorage

### Security recommendations

- ✅ Always set a strong `AUTH_TOKEN` in production
- ✅ Use HTTPS (see SSL section)
- ✅ Rotate tokens periodically
- ✅ Keep token secret - don't commit to git
- ⚠️ If token is compromised, change it immediately

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ENABLED` | `true` | Enable/disable authentication |
| `AUTH_TOKEN` | (auto-generated) | Authentication token for dashboard access |
| `UPDATE_INTERVAL` | 60 | Update interval (seconds) |
| `RETENTION_DAYS` | 90 | Session retention (days) |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | 30 | Chart data retention (days) |

## API

All API endpoints (except `/api/login` and `/api/check_auth`) require authentication header:

```bash
Authorization: Bearer YOUR_TOKEN
```

### Endpoints

- `POST /api/login` - Verify token and login
- `GET /api/check_auth` - Check if auth is enabled
- `GET /api/health` - Health check
- `GET /api/servers` - Server list
- `GET /api/summary` - Summary stats
- `GET /api/active_sessions?server=NAME` - Active sessions
- `GET /api/user_stats?server=NAME&limit=50&search=user` - User stats
- `GET /api/traffic_chart?server=NAME&hours=24` - Traffic data
- `GET /api/user_traffic_chart?users=user1,user2&hours=24` - User comparison chart data
- `GET /api/user_sessions/<username>?server=NAME` - User sessions list
- `GET /api/users_list?server=NAME` - All users list for dropdown
- `GET /api/export/sessions?format=csv` - Export sessions
- `GET /api/export/users?format=json` - Export users

### Example API call

```bash
curl -H "Authorization: Bearer your-token-here" \
  http://localhost/api/summary
```

## User Comparison Feature

Compare traffic consumption of multiple users on a single chart.

### How to use

1. **Via dropdown**: Select users from "Add user to compare" dropdown
2. **Via tables**: Click on username in Active Sessions or User Statistics tables
3. **View sessions**: Click 📋 icon next to username to see all sessions
4. **Compare**: Up to 10 users can be compared simultaneously

### Features

- Real-time traffic comparison chart
- Per-user statistics cards (download/upload totals)
- Session details modal (active + recent 7 days)
- Color-coded visualization
- Time range selector (1h, 6h, 24h, 7d)

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
