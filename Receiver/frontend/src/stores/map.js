import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { getActiveDrones, getDrone } from '@/api/api'
import { getDroneLocation, LiveVisualizationStrategy, updateLiveDroneLocation } from './visualization/LiveVisualizationStrategy'
import { ReplayVisualizationStrategy } from './visualization/ReplayVisualizationStrategy'


class ActiveDrone {
  constructor(serial_number, home_position, pilot_position) {
    this.serial_number = serial_number
    this.show_path = false
    this.show_pilot = false
    this.show_home = false

    this.home_position = home_position
    this.pilot_position = pilot_position
  }
}

export const useMapStore = defineStore('map', () => {
  // State
  const activeDrones = ref([]) // Map of Drones keyed by serial_number
  const focusedDrone = ref(null) // The drone that is centered on the map
  const infoDrone = ref(null) // The drone that is getting displayed in the Drone Info panel

  const replayDrone = ref(null) // The drone that is being replayed
  const replayPath = ref([]) // The path that is being replayed, also reffered to as flight
  const replayTimeStep = ref(0) // The current time step of the replay

  // Computed
  const replayModeIsActive = computed(() => replayPath.value.length > 0)
  const replayLength = computed(() => replayPath.value.length)

  // Visualization strategies
  const liveStrategy = new LiveVisualizationStrategy(activeDrones)
  const replayStrategy = new ReplayVisualizationStrategy(replayDrone, replayPath, replayTimeStep)

  // Initialize
  async function loadActiveDrones() {
    const drones = await getActiveDrones()
    drones.forEach(drone => {
      updateDroneLocation(drone.sender_id, [drone.position.lng, drone.position.lat])
    })

    activeDrones.value = drones.map(drone => new ActiveDrone(drone.sender_id))
  }

  async function setInfoDrone(serialNumber) {
    const drone_dto = await getDrone(serialNumber)
    infoDrone.value = drone_dto
  }

  // Drone updates
  function updateDroneLocation(serialNumber, position) {
    updateLiveDroneLocation(serialNumber, position)
  }

  // Replay functionality
  function setReplayPath(drone, path) {
    replayDrone.value = drone
    replayPath.value = path
    replayTimeStep.value = 0
  }

  function setReplayTimeStep(step) {
    replayTimeStep.value = step
  }

  function getVisualizationStrategy() {
    return replayModeIsActive.value ? replayStrategy : liveStrategy
  }

  function getFocusedDroneLocation() {
    if (!focusedDrone.value) return null

    if (replayModeIsActive.value) {
      return replayStrategy.getDroneFeatures().features[0].geometry.coordinates
    } else {
      return getDroneLocation(focusedDrone.value.serial_number)
    }
  }

  function getInfoDroneLocation() {
    if (!infoDrone.value) return null

    if (replayModeIsActive.value) { 
      return replayStrategy.getDroneFeatures().features[0].geometry.coordinates
    } else {
      return getDroneLocation(infoDrone.value.serial_number)
    }
  }

  return {
    // State
    activeDrones,
    focusedDrone,
    infoDrone,
    replayPath,
    replayTimeStep,
    replayModeIsActive,
    replayLength,

    // Methods
    loadActiveDrones,
    updateDroneLocation,
    setReplayPath,
    setReplayTimeStep,
    getVisualizationStrategy,
    getFocusedDroneLocation,
    getInfoDroneLocation,
    setInfoDrone,
  }
})
