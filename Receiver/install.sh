#!/usr/bin/env bash

# parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--port)
      PORT="$2"
      shift # pass argument
      shift # pass value
      ;;
    -h|--help)
      echo "Installs drone sniffer software into /opt/dsniffer, please run as super user."
      echo "Use -p, --port to specify which port the app should run on (default 80)"
      exit 0
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

# set port
PORT=${PORT:-80}
export PORT
echo "Using port $PORT"

# Install python and pip

echo "Installing python and pip..."
apt -y install python3 python3-pip libatlas-base-dev

# Install python dependencies
echo "Installing dependencies..."
pip3 install -r ./requirements.txt

# copy repository files
echo "Installing dsniffer into /opt/dsniffer..."
mkdir -p /opt/dsniffer
cp -r ./backend/ /opt/dsniffer/backend/
cp -r ./frontend/ /opt/dsniffer/frontend/

# Install dsniffer service
cat ./dsniffer.service | envsubst > /etc/systemd/system/dsniffer.service
systemctl daemon-reload
systemctl enable dsniffer
systemctl start dsniffer

echo "Installed and ready to use. Visit http://$(hostname):$PORT"
