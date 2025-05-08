import axios from 'axios'
import { initializeMocks, initializeMockWebServer } from './mock'
import { useMapStore } from '@/stores/map'

class Drone {
  constructor(drone) {
    Object.assign(this, drone)
    this.show_path = false
    this.show_pilot = false
    this.show_home = false
    this.flights = undefined

    this.position = [drone.position.lng, drone.position.lat]
    this.pilot_position = [drone.pilot_position.lng, drone.pilot_position.lat]
    this.home_position = [drone.home_position.lng, drone.home_position.lat]
  }
}

let client = axios
let isInitialized = false
if (import.meta.env.DEV && !isInitialized) {
  console.log('Development mode, mocking http requests')
  // client = initializeMocks()
  // initializeMockWebServer()
  isInitialized = true
  axios.defaults.baseURL = 'http://localhost:3001';
}

async function getJsonResponse(url) {
  return (await client.get(url)).data
}

export const getDrone = async (serial_number) => {
  const drone = await getJsonResponse(`/api/drones/${serial_number}`)
  return new Drone(drone)
}

export const getSettings = async () => getJsonResponse('/api/settings')
export const getInterfaces = async () => getJsonResponse('/api/settings/interfaces')
export const getActiveDrones = async () => getJsonResponse('/api/drones/active')
export const getAllDrones = async () => getJsonResponse('/api/drones/all')
export const getHistory = async (serial_number) =>
  getJsonResponse(`/api/drones/${serial_number}/history`)
export const getFlights = async (serial_number) =>
  getJsonResponse(`/api/drones/${serial_number}/flights`)
export const getFlight = async (serial_number, flight_timestamp) => {
  const url_timestamp = encodeURIComponent(flight_timestamp)
  return await getJsonResponse(`/api/drones/${serial_number}/flights/${url_timestamp}`)
}

export const postSettings = async (settings) => {
  const response = await client.post('/api/settings', settings)
  if (response.status !== 200) throw new Error('Settings update failed.')
  return await response.data
}

export const initWebSocket = () => {
  const store = useMapStore();

  const ws = new WebSocket(`ws://${window.location.host}/ws`);
  ws.onmessage = (event) => {
    const drone = JSON.parse(event.data);
    store.updateDroneLocation(drone.sender_id, [drone.position.lng, drone.position.lat])
  };
}
