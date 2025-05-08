
const dronePositionsMap = new Map()
const dronePathsMap = new Map()

export function getDroneLocation(serialNumber) {
  if(!dronePositionsMap.has(serialNumber)) {
    return null
  }
  return dronePositionsMap.get(serialNumber).geometry.coordinates
}

export function updateLiveDroneLocation(serialNumber, position) {
  if(!dronePositionsMap.has(serialNumber)) {
    dronePositionsMap.set(serialNumber, {
      type: 'Feature',
      properties: {serialNumber},
      geometry: { type: 'Point', coordinates: position },
    })
  }

  if(!dronePathsMap.has(serialNumber)) {
    dronePathsMap.set(serialNumber, {
      type: 'Feature',
      properties: {},
      geometry: { type: 'LineString', coordinates: [] },
    })
  }
    
  dronePositionsMap.get(serialNumber).geometry.coordinates = position
  dronePathsMap.get(serialNumber).geometry.coordinates.push([position[0], position[1]])
}


export class LiveVisualizationStrategy {
  constructor(activeDrones) {
    this.activeDrones = activeDrones
  }



  getDroneFeatures() {
    return {
      type: 'FeatureCollection',
      features: this.activeDrones.value
        .map(drone => dronePositionsMap.get(drone.serial_number))
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
        .map(drone => dronePathsMap.get(drone.serial_number)),
    }
  }
}
