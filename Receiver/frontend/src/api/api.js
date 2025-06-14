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
  client = initializeMocks()
  initializeMockWebServer()
  isInitialized = true
}

async function getJsonResponse(url) {
  return (await client.get(url)).data
}

export const getDrone = async (sender_id) => {
  const drone = await getJsonResponse(`/api/drones/${sender_id}`)
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
  if(import.meta.env.DEV) return; // WebSocket is not required in mock mode

  const store = useMapStore();

  let wsl = "ws://" + window.location.host + "/ws"

  const ws = new WebSocket(wsl);
  ws.onmessage = (event) => {
    const drones = JSON.parse(event.data);
    for (const drone of drones) {
      store.updateDroneLocation(drone.sender_id, [drone.position.lng, drone.position.lat])
    }
  };
}
