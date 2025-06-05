FROM python:3.13-bookworm

WORKDIR /app

# Copy backend requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY backend/ ./backend/

# Copy the built frontend
COPY ./frontend/dist ./frontend/dist/

COPY pytest.ini pytest.ini
COPY .coveragerc .coveragerc

# Set environment variables
ENV PYTHONPATH=/app

# Command to run the application
CMD ["python", "backend/dronesniffer/main.py"]
