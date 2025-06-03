# Drone Monitoring Web Application

A web-based application for monitoring and tracking drones using WiFi signals. This application captures drone telemetry data through a WiFi adapter in monitor mode and displays the information on an interactive map interface.

## Features
- Real-time drone detection and tracking
- Interactive map visualization
- Support for multiple map services
- Offline capability with self-hosted tile server
- Web-based interface accessible from any device

## Prerequisites
- Docker and Docker Compose
- Python 3.8 or higher
- WiFi adapter with monitor mode support (e.g., [Archer T2U Plus](https://www.tp-link.com/de/home-networking/adapter/archer-t2u-plus/))
- Linux-based operating system (for WiFi monitor mode support)
- Sudo privileges (required for monitor mode access)

*Note:  Regular wifi cards often lack support of monitoring-mode. This mode is required to listen to all network traffic.*

## Installation

### 1. Clone the Repository
```bash
git clone git@github.com:cyber-defence-campus/DroneIDReceiver.git
cd RemoteIDReceiver
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

*Note: While containerization is possible, direct installation is recommended due to hardware-specific requirements for WiFi monitor mode.*

### 3. Configure the Application
1. Create a configuration file:
```bash
cp .env.example .env
```

2. Configure map service:
- Default: Free map with basic details
- Google Maps: Uncomment `FRONTEND_MAP_STYLE=google` and add your [Google Maps API Key](https://developers.google.com/maps/documentation/javascript/get-api-key)
- Self-hosted: Configure your own tile server for offline functionality

### 4. Build the Frontend
The following command builds your frontend using your configured map.
```bash
docker-compose up build-frontend
```

## Running the Application
You can run the app with:
```bash
sudo python3 ./Receiver/backend/dronesniffer/main.py -p 80
```
The web interface will be available at `http://localhost:80` (or your specified port).

*Note: Sudo privileges are required for WiFi monitor mode access.*

### Service Mode (Systemd Service)
1. Start the service:
```bash
sudo systemctl start dsniffer.service
```

2. Stop the service:
```bash
sudo systemctl stop dsniffer.service
```

3. Check service status:
```bash
sudo systemctl status dsniffer.service
```

## Frontend Development
If you want to develop on the frontend, you can spawn a development-server with:
```bash
docker-compose up dev-frontend
```

## Troubleshooting

### Common Issues
1. **WiFi Adapter Not Working in Monitor Mode**
   - Ensure your adapter supports monitor mode
   - Check if you have the correct drivers installed
   - Verify you're running the application with sudo privileges

2. **Map Not Loading**
   - Verify your internet connection
   - Check if your API key is valid (if using Google Maps)
   - Ensure the frontend was built successfully
