FROM node:20-alpine AS frontend-build

WORKDIR /app

# Define build arguments with defaults
ARG FRONTEND_BUILD_COMMAND=build:google
ARG STYLE_URL

# Copy frontend files
COPY frontend_new/package*.json ./frontend_new/
WORKDIR /app/frontend_new
RUN npm ci

COPY frontend_new/ ./

# Use the build command from arguments
RUN if [ -z "$STYLE_URL" ]; then \
        npm run ${FRONTEND_BUILD_COMMAND}; \
    else \
        npm run build --style-url=${STYLE_URL}; \
    fi

# Backend stage
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (libpcap for packet capturing)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    libatlas-base-dev \
    wireless-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend code
COPY backend/ ./backend/
COPY resources/ ./resources/

# Copy the built frontend from the build stage
COPY --from=frontend-build /app/frontend_new/dist ./frontend_new/dist/

# Set environment variables
ENV PYTHONPATH=/app

# Expose the port the app runs on
EXPOSE 80

# Command to run the application
CMD ["python", "backend/dronesniffer/main.py"] 