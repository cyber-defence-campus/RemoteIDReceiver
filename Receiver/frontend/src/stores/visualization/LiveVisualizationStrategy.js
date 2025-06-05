
const dronePositionsMap = new Map()
const dronePathsMap = new Map()

export function getDroneLocation(sender_id) {
  if(!dronePositionsMap.has(sender_id)) {
    return null
  }
  return dronePositionsMap.get(sender_id).geometry.coordinates
}

export function updateLiveDroneLocation(sender_id, position) {
  if(!dronePositionsMap.has(sender_id)) {
    dronePositionsMap.set(sender_id, {
      type: 'Feature',
      properties: {serialNumber: sender_id},
      geometry: { type: 'Point', coordinates: position },
    })
  }

  if(!dronePathsMap.has(sender_id)) {
    dronePathsMap.set(sender_id, {
      type: 'Feature',
      properties: {},
      geometry: { type: 'LineString', coordinates: [] },
    })
  }
    
  dronePositionsMap.get(sender_id).geometry.coordinates = position
  dronePathsMap.get(sender_id).geometry.coordinates.push([position[0], position[1]])
}


export class LiveVisualizationStrategy {
  constructor(activeDrones) {
    this.activeDrones = activeDrones
  }



  getDroneFeatures() {
    return {
      type: 'FeatureCollection',
      features: this.activeDrones.value
        .map(drone => dronePositionsMap.get(drone.sender_id))
        .filter(feature => feature && feature.geometry.coordinates !== undefined)
    }
  }

  getPilotFeatures() {
    return {
      type: 'FeatureCollection',
      features: this.activeDrones.value
        .filter(drone => drone.show_pilot)
        .map(drone => drone.pilot_position)
        .map(position => ({
          type: 'Feature',
          properties: {},
          geometry: { type: 'Point', coordinates: position },
        }))
        .filter(feature => feature.geometry.coordinates !== undefined)
    }
  }

  getHomeFeatures() {
    return {
      type: 'FeatureCollection',
      features: this.activeDrones.value
        .filter(drone => drone.show_home)
        .map(drone => drone.home_position)
        .map(position => ({
          type: 'Feature',
          properties: {},
          geometry: { type: 'Point', coordinates: position },
        }))
        .filter(feature => feature.geometry.coordinates !== undefined)
    }
  }

  getPaths() {
    return {
      type: 'FeatureCollection',
      features: this.activeDrones.value
        .filter(drone => drone.show_path)
        .map(drone => dronePathsMap.get(drone.sender_id)),
    }
  }
}
