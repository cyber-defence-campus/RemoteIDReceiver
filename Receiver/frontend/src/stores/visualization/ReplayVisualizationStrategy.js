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
          serialNumber: drone.sender_id,
        },
        geometry: {
          type: 'Point',
          coordinates: [location.position.lng, location.position.lat],
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
          coordinates: this.replay_path.value.map(location => [location.position.lng, location.position.lat]).slice(0, this.replay_time_step.value + 1),
        },
      }],
    }
  }
}
