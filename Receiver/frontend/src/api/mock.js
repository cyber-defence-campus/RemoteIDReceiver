import { useMapStore } from '@/stores/map'
import { get } from '@vueuse/core'
import axios from 'axios'
import AxiosMockAdapter from 'axios-mock-adapter'

/**
 * DEV MOCKING DATA
 * THIS DATA IS INTENDED TO BE USED FOR FRONTEND DEVELOPMENT PURPOSES ONLY
 */

const mock_drone = {
  serial_number: 'mock-drone-1',
  position: {
    lat: 46.94809,
    lng: 7.44744,
  },

  pilot_position: {
    lat: 46.94809,
    lng: 7.44744,
  },
  home_position: {
    lat: 46.94809,
    lng: 7.44744,
  },
  rotation: 10,
  altitude: 1100,
  height: 1000,
  x_speed: 5,
  y_speed: 4,
  z_speed: 3,
  spoofed: true,
  flights: ['2025-03-01T11:51:52.618Z'],
}

let mock_drone_old = JSON.parse(JSON.stringify(mock_drone))
mock_drone_old.serial_number = 'mock-drone-2'

const mock_drone_history = [
  {
    timestamp: '2025-03-01T11:51:52.618Z',
    position: {
      latitude: 46.94809,
      longitude: 7.44744,
    },
  },
  {
    timestamp: '2025-03-01T11:51:54.428Z',
    position: {
      latitude: 46.94809,
      longitude: 7.44754,
    },
  },
  {
    timestamp: '2025-03-01T11:51:56.428Z',
    position: {
      latitude: 46.95809,
      longitude: 7.44954,
    },
  },
]

const settings = {
  google_maps_api_key: null,
  activity_offset_in_m: 10,
  drone_size_in_rem: 5,
  interfaces: ['test-interface-1', 'test-interface-2'],
}

function getDrones(n = 1) {
  let drones = []
  for (let i = 1; i <= n; i++) {
    let drone = {
      position: [7.44744 + 0.01 * Math.random(), 46.94809 + 0.01 * Math.random()],
      serial_number: `mock-drone-${i}`,
    }
    drones.push(drone)
  }
  return drones
}
const drones = getDrones(10)

export function initializeMocks() {
  const mock = new AxiosMockAdapter(axios)
  mock.onGet('/api/drones/active').reply(200, drones.map(drone => drone.serial_number))
  mock.onGet('/api/drones/all').reply(200, ["mock-drone-2"])
  mock.onGet('/api/drones/mock-drone-1').reply(200, mock_drone)
  mock.onGet('/api/drones/mock-drone-2').reply(200, mock_drone_old)
  mock.onGet('/api/drones/mock-drone-1/history').reply(200, mock_drone_history)
  mock.onGet('/api/drones/mock-drone-2/flights').reply(200, [mock_drone_history[0].timestamp])
  mock.onGet('/api/drones/mock-drone-1/flights').reply(200, [])
  mock
    .onGet('/api/drones/mock-drone-2/flights/2025-03-01T11%3A51%3A52.618Z')
    .reply(200, mock_drone_history)
  mock.onGet('/api/settings').reply(200, settings)
  mock.onPost('/api/settings').reply(function (config) {
    const data = JSON.parse(config.data)
    settings.google_maps_api_key = data.google_maps_api_key
    settings.activity_offset_in_m = data.activity_offset_in_m
    settings.drone_size_in_rem = data.drone_size_in_rem
    return [200, settings]
  })
  mock.onGet('/api/settings/interfaces').reply(200, settings.interfaces)
  return axios
}

let fakeLocation = [46.94809, 7.44744]

export function initializeMockWebServer() {
  setTimeout(() => {
    const store = useMapStore()

  function updateDronePositions() {
    
    for (let drone of drones) {
      fakeLocation = drone.position
      fakeLocation[1] += 0.0001 * Math.random()
      fakeLocation[0] += 0.0001 * Math.random()
      store.updateDroneLocation(drone.serial_number, fakeLocation)
    }
    
     setTimeout(updateDronePositions, 2000); // Update every 2 seconds
  }
  
  // Start the animation
  updateDronePositions();
  }, 1000)
}
