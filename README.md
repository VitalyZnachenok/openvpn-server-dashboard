# OpenVPN Server Dashboard

**English** | [Русский](README.ru.md)

Multi-server OpenVPN monitoring and statistics visualization system with web interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue.svg)

## 📋 Features

- 🖥️ **Multi-Server Support** - Monitor multiple OpenVPN servers simultaneously
- 📊 **Traffic Visualization** - Interactive charts for inbound and outbound traffic
- 👥 **Active Connection Monitoring** - Real-time tracking of current users
- 📈 **User Statistics** - Detailed information for each user
- 💾 **SQLite Database** - Store session and traffic history
- 🔄 **Automatic Updates** - Data refresh every minute (configurable)
- 📥 **Data Export** - Export statistics to CSV and JSON formats
- 🐳 **Docker Containerization** - Easy deployment with Docker Compose
- 🔒 **Nginx with SSL** - Ready-to-use reverse proxy configuration with HTTPS support
- 🧹 **Automatic Cleanup** - Remove old data according to retention policy

## 📸 Interface

The dashboard provides:
- Summary information (active users, total users, today's sessions, total traffic)
- Traffic charts for different periods (5 min, 30 min, 1 hour, 6 hours, 24 hours, week)
- Active session table with connection details
- User statistics with filtering and search

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- OpenVPN server with status file enabled
- (Optional) Nginx for HTTPS and basic authentication

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/openvpn-server-dashboard.git
cd openvpn-server-dashboard
```

2. **Configure OpenVPN servers:**

Edit `docker-compose.yml` and specify your servers in the `SERVERS_CONFIG` variable:

```yaml
environment:
  - SERVERS_CONFIG=
      server1:/var/log/openvpn/server1-status.log:/var/log/openvpn/server1.log;
      server2:/var/log/openvpn/server2-status.log:/var/log/openvpn/server2.log
```

Format: `SERVER_NAME:STATUS_FILE:LOG_FILE`

**For a single server:**
```yaml
environment:
  - OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
  - OPENVPN_LOG_FILE=/var/log/openvpn/openvpn.log
```

3. **Create data directory:**
```bash
mkdir -p data
```

4. **Start with Docker Compose:**
```bash
make up
# or
docker-compose up -d
```

5. **Open in browser:**
```
http://localhost:80
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `SERVERS_CONFIG` | Multiple servers configuration (format: NAME:STATUS:LOG) | - |
| `OPENVPN_STATUS_FILE` | Path to OpenVPN status file (single server) | `/var/log/openvpn/openvpn-status.log` |
| `OPENVPN_LOG_FILE` | Path to OpenVPN log file (single server) | `/var/log/openvpn/openvpn.log` |
| `DB_PATH` | Path to SQLite database | `/app/data/openvpn_stats.db` |
| `UPDATE_INTERVAL` | Data update interval (in seconds) | `60` |
| `RETENTION_DAYS` | Session retention period (in days) | `90` |
| `TRAFFIC_HISTORY_RETENTION_DAYS` | Traffic history retention period (in days) | `30` |
| `DEFAULT_LIMIT` | Default records limit | `50` |
| `MAX_LIMIT` | Maximum records limit | `500` |
| `FLASK_PORT` | Flask application port | `5000` |
| `FLASK_HOST` | Flask application host | `0.0.0.0` |

### OpenVPN Configuration

For the dashboard to work, OpenVPN must write a status file. Add to your OpenVPN server configuration:

```bash
status /var/log/openvpn/openvpn-status.log
status-version 2
```

### Nginx and SSL

1. **Create SSL certificate:**
```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt
```

2. **Setup basic authentication (optional):**
```bash
# Install apache2-utils
apt-get install apache2-utils

# Create password file
htpasswd -c nginx/.htpasswd admin
```

3. **Edit `nginx/sites-enabled/vpn-stats.conf`** for your domain

## 🛠️ Makefile Commands

The project includes a Makefile for easy management:

```bash
make help      # Show help
make build     # Build Docker images
make up        # Start services
make down      # Stop services
make restart   # Restart services
make logs      # View logs
make clean     # Clean data and stop containers
make shell     # Enter container shell
make tail-logs # View last 100 lines of logs
```

## 📡 API Endpoints

The dashboard provides a REST API for integration:

### General
- `GET /api/health` - Service health check
- `GET /api/servers` - List of configured servers
- `GET /api/summary` - Summary statistics

### Sessions
- `GET /api/active_sessions?server=SERVER_NAME` - Active sessions
- `GET /api/export/sessions?format=csv&server=SERVER_NAME` - Export active sessions

### User Statistics
- `GET /api/user_stats?server=SERVER_NAME&limit=50&offset=0&search=username` - User statistics
- `GET /api/export/users?format=json&server=SERVER_NAME` - Export statistics

### Charts
- `GET /api/traffic_chart?server=SERVER_NAME&hours=24` - Traffic data for charts

**Parameters:**
- `server` - (optional) server name for filtering
- `hours` - period for charts (0.083 = 5 min, 0.5 = 30 min, 1, 6, 24, 168 = week)
- `format` - export format (csv or json)
- `limit` - number of records
- `offset` - offset for pagination
- `search` - search by username

## 📊 Database Structure

### `sessions` Table
Stores VPN session information:
- username, server_name, real_address, virtual_address
- bytes_received, bytes_sent
- connected_since, disconnected_at, session_duration

### `user_stats` Table
Aggregated user statistics:
- username, server_name
- total_sessions, total_time_seconds
- total_bytes_sent, total_bytes_received
- last_seen, current_status

### `traffic_history` Table
Traffic history for chart generation:
- server_name, username (optional)
- bytes_in, bytes_out, active_users
- timestamp

## 🔧 Development

### Local Run (without Docker)

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Set environment variables:**
```bash
export DB_PATH=./data/openvpn_stats.db
export OPENVPN_STATUS_FILE=/var/log/openvpn/openvpn-status.log
export UPDATE_INTERVAL=60
```

3. **Run the application:**
```bash
python app.py
```

### Project Structure

```
openvpn-server-dashboard/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker image
├── docker-compose.yml          # Docker Compose configuration
├── Makefile                   # Management commands
├── templates/
│   └── index.html             # HTML interface template
├── static/                    # Static files (CSS, JS)
├── nginx/
│   ├── nginx.conf             # Nginx configuration
│   ├── sites-enabled/
│   │   └── vpn-stats.conf    # Virtual host
│   └── ssl/                   # SSL certificates
├── data/                      # SQLite database (auto-created)
└── LICENSE
```

## 🐛 Troubleshooting

### Issue: Status file not found

Make sure that:
1. OpenVPN is configured to create a status file
2. The path to the status file in docker-compose.yml is correct
3. The volume is mounted correctly

### Issue: No data in charts

- Wait a few minutes after startup (data is collected on schedule)
- Check that there are active VPN connections
- Check logs: `make logs`

### Issue: Database connection error

```bash
# Check data directory permissions
chmod 755 data/

# Or recreate the container
make clean
make up
```

## 📝 License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📧 Contact

If you have questions or suggestions, create an issue in the repository.

## ⭐ Acknowledgments

- Flask and Python ecosystem
- Chart.js for visualization
- OpenVPN community

---

**Note:** This dashboard is designed for OpenVPN version 2.5+ with status-version 2.
