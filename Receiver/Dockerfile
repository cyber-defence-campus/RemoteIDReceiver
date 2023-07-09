FROM python:3.10-slim-bookworm

# Set environment variable PORT with a default value
ENV PORT 80

# Set working directory
WORKDIR /opt/dsniffer

# Copy requirements.txt to install dependencies
COPY ./requirements.txt ./requirements.txt

# Install required packages and Python dependencies
RUN apt update && apt install -y \
      libatlas-base-dev \
      wireless-tools \
      iproute2 \
    && pip install -r ./requirements.txt \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy over code last for faster container rebuilds
COPY ./backend/ ./backend/
COPY ./frontend ./frontend/

# The command to run the app when the docker container is started
CMD ["sh", "-c", "python3 /opt/dsniffer/backend/dronesniffer/main.py -p $PORT"]
