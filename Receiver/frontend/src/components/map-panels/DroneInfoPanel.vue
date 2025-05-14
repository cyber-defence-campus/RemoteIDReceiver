<template>
  <div class="bg-white rounded shadow-xl p-4 min-w-[300px]" v-if="infoDrone">
    <!-- Header -->
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Drone Information</h2>
      <button @click="closePanel" class="p-2 hover:bg-gray-100 rounded">❌</button>
    </div>

    <!-- Content -->
    <div class="flex flex-col gap-4">
      <!-- Serial Number -->
      <div class="flex justify-between items-center">
        <span class="text-gray-600">Serial Number</span>
        <span class="font-medium">{{ infoDrone.serial_number }}</span>
      </div>

      <!-- Positions -->
      <div class="flex flex-col gap-2">
        <div v-if="infoDrone?.position" class="flex justify-between items-center">
          <span class="text-gray-600">Drone position</span>
          <span class="font-medium">{{ geoPointToText(droneLocation) }}</span>
        </div>
        <div v-if="infoDrone?.pilot_position" class="flex justify-between items-center">
          <span class="text-gray-600">Pilot position</span>
          <span class="font-medium">{{ geoPointToText(infoDrone.pilot_position) }}</span>
        </div>
          <div v-if="infoDrone?.home_position" class="flex justify-between items-center">
          <span class="text-gray-600">Home position</span>
          <span class="font-medium">{{ geoPointToText(infoDrone.home_position) }}</span>
        </div>
      </div>

      <!-- Metrics -->
      <div class="flex flex-col gap-2">
        <div class="flex justify-between items-center">
          <span class="text-gray-600">Speed xyz</span>
          <span class="font-medium"
            >{{ infoDrone.x_speed }} {{ infoDrone.y_speed }} {{ infoDrone.z_speed }}</span
          >
        </div>
        <div class="flex justify-between items-center">
          <span class="text-gray-600">Altitude</span>
          <span class="font-medium">{{ infoDrone.altitude }} m</span>
        </div>
        <div class="flex justify-between items-center">
          <span class="text-gray-600">Pilot Height</span>
          <span class="font-medium">{{ infoDrone.height }} m</span>
        </div>
      </div>

      <!-- Track Button -->
      <button
        title="Track drone"
        @click="flyToDrone(infoDrone)"
        class="mt-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 border border-gray-200"
        style="border-radius: 3px !important"
      >
        🎯
      </button>

      <!-- Flights List -->
      <div v-if="flights?.length" class="mt-4">
        <h3 class="text-lg font-semibold mb-2">Previous Flights</h3>
        <div
          v-for="flight in flights"
          :key="flight"
          class="flex justify-between items-center py-2 border-b border-gray-200 last:border-0"
        >
          <span>{{ formatTimestamp(flight) }}</span>
          <button
            title="Replay flight"
            @click="replayFlight(infoDrone.serial_number, flight)"
            class="p-2 hover:bg-gray-100 rounded"
          >
            ▶️
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onDeactivated, onMounted, ref, nextTick } from 'vue'
import { storeToRefs } from 'pinia'
import { computedAsync } from '@vueuse/core'
import { useMapStore } from '@/stores/map'
import { getFlight, getFlights } from '@/api/api'

// Store initialization
const mapStore = useMapStore()
const { infoDrone, focusedDrone } = storeToRefs(mapStore)

const droneLocation = ref(null)
function pollDrone() {
  const location = mapStore.getInfoDroneLocation()

  if (location) {
    const location_copy = [...location] // necessary to update the ref
    droneLocation.value = location_copy
  }
  
  setTimeout(pollDrone, 1000)
}

onMounted(() => {
  pollDrone()
})

// Emits
const emits = defineEmits(['fly-to'])

// Computed properties
const flights = computedAsync(async () => {
  if (!infoDrone.value) return []
  return await getFlights(infoDrone.value.serial_number)
})

// Methods
function flyToDrone(drone) {
  focusedDrone.value = drone
  const location = mapStore.getFocusedDroneLocation()
  emits('fly-to', location)
}

function closePanel() {
  infoDrone.value = null
}

async function replayFlight(serial_number, flight_date) {
  const flight = await getFlight(serial_number, flight_date)
  mapStore.setReplayPath(infoDrone.value, flight)
  flyToDrone(infoDrone.value)
}

function geoPointToText(coordinates) {
  if (!coordinates) return ''
  return `${coordinateToText(coordinates[0])}, ${coordinateToText(coordinates[1])}`
}

function coordinateToText(decimal) {
  if (!decimal) return ''
  const degrees = Math.round(decimal)
  decimal = (decimal - degrees) * 60
  const minutes = Math.round(decimal)
  decimal = (decimal - minutes) * 60
  const seconds = Math.round(decimal * 10000) / 10000
  return `${degrees}° ${minutes}' ${seconds}''`
}

function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleString()
}
</script>
