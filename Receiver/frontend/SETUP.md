# Development Environment Setup

This guide explains how to set up the development environment for the Vue.js application and documentation generation using Docker.

## Prerequisites

1. Docker Desktop (Windows/Mac) or Docker Engine (Linux)
2. Git (for version control)

## Getting Started

Start the development environment:

```bash
docker compose up
```

This will:

- Start the Vue.js development server on port 3000
- Set up hot-reloading for development
- Build the docs

## Available Services

### Vue.js Application (`app` service)

- Development server runs at: http://localhost:3000
- Hot-reloading enabled for development
- Source code is mounted from local directory

### Documentation Generation (`docs` service)

- Generates architecture documentation from AsciiDoc files
- Output is saved to `docs/dist/architecture.html`
- Supports PlantUML diagrams with SVG output

### Production Build (`build` service)

- Creates a production-optimized build of the Vue.js application
- Output is saved to the `dist` directory

## Development Workflow

### Starting the Development Environment

```bash
# Start all services
docker compose up

# Start only specific service
docker compose up app    # For Vue.js development
docker compose up docs   # For documentation generation
docker compose up build # For a production build
```
