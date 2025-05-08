export class ReplayVisualizationStrategy {
  constructor(replayDrone, replay_path, replay_time_step) {
    this.replayDrone = replayDrone
    this.replay_path = replay_path
    this.replay_time_step = replay_time_step
  }

  getDroneFeatures() {
    const drone = this.replayDrone.value
    const location = this.replay_path.value[this.replay_time_step.value]

    return {
      type: 'FeatureCollection',
      features: [{
        type: 'Feature',
        properties: {
          serialNumber: drone.serial_number,
        },
        geometry: {
          type: 'Point',
          coordinates: [location.position.longitude, location.position.latitude],
        },
      }],
    }
  }

  getPilotFeatures() {
    return {
      type: 'FeatureCollection',
      features: [{
        type: 'Feature',
        properties: {},
        geometry: {
          type: 'Point',
          coordinates: this.replayDrone.value.pilot_position,
        },
      }],
    }
  }
  

  getHomeFeatures() {
    return {
      type: 'FeatureCollection',
      features: [{
        type: 'Feature',
        properties: {},
        geometry: {
          type: 'Point',
          coordinates: this.replayDrone.value.home_position,
        },
      }],
    }
  }

  getPaths() {
    return {
      type: 'FeatureCollection',
      features: [{
        type: 'Feature',
        properties: {},
        geometry: {
          type: 'LineString',
          coordinates: this.replay_path.value.map(location => [location.position.longitude, location.position.latitude]).slice(0, this.replay_time_step.value + 1),
        },
      }],
    }
  }
}
