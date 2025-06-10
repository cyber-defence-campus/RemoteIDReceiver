# Remote ID Receiver Frontend

A Vue.js-based web application for monitoring and tracking drones in real-time using MapLibre GL JS.

## Features

- Real-time drone tracking on an interactive map
- Replay mode for historical data
- Settings panel for configuration
- Responsive design

## Project Structure

```
src/
├── api/           # API integration layer
├── assets/        # Static assets
├── components/    # Vue components
│   ├── map-panels/    # Map-related UI components
│   └── MapView.vue    # Main map component
├── stores/        # Pinia state management
└── main.js        # Application entry point
```

## Key Components

### MapView.vue

The main component that handles the map visualization and UI layout. It includes:

- `SettingsPanel`: Configuration options
- `ActiveDoneListPanel`: List of currently active drones
- `AllDroneListPanel`: Complete list of all drones
- `DroneInfoPanel`: Detailed information about selected drone
- `ReplayControls`: Controls for replay mode

## Dependencies

- Vue.js
- Pinia (State Management)
- MapLibre GL JS
- Font Awesome Icons

## Map Configuration

The application supports multiple map styles:

- Basic preview style (default)
- Google Maps style (requires API key)
- Swiss topographic maps
- Demo tiles

## Screenshots

![Overview](../resources/images/screen_live.png 'Overview')
![Replay](../resources/images/screen_replay.png 'Replay')

## Development

Installation instructions are under [Setup](./SETUP.md).

## Documentation

Documentation is avaiable under [Doc](https://svenfahrni.github.io/remoteid-frontend-clone/architecture.pdf). 
The Documentation follows the [C4-Model](https://c4model.com/) and is still wip, although the diagrams are correct.
