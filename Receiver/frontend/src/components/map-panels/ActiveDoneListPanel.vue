<template>
  <div class="bg-white rounded-lg shadow-lg p-3">
    <h2 class="text-lg font-semibold mb-3 text-gray-800">Active Drones</h2>
    <div class="table-container">
      <table class="w-full">
        <thead>
          <tr class="border-b border-gray-200">
            <th>Serial Number</th>
            <th title="Track Drone">🎯</th>
            <th title="Drone Info">📊</th>
            <th title="Show Flight Path">🚁</th>
            <th title="Show Pilot">👨‍✈️</th>
            <th title="Show Home">🏠</th>
          </tr>
        </thead>
        <tbody class="table-body">
          <tr v-for="drone in Array.from(activeDrones.values())" :key="drone"
            class="cursor-pointer">
            <td>
              <span class="text-gray-700 text-sm">{{ drone.serial_number }}</span>
            </td>
            <td>
              <button title="Track drone" @click.stop.prevent="flyToDrone(drone)">🎯</button>
            </td>
            <td>
              <button title="Show Drone Info" @click.stop.prevent="showDroneInfo(drone)">📊</button>
            </td>
            <td>
              <input v-model="drone.show_path" type="checkbox" title="Show Flight Path" />
            </td>
            <td>
              <input v-model="drone.show_pilot" type="checkbox" title="Show Pilot" @change="updateDrone(drone)" />
            </td>
            <td>
              <input v-model="drone.show_home" type="checkbox" title="Show Home" @change="updateDrone(drone)" />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
<script setup>
import { storeToRefs } from 'pinia'
import { useMapStore } from '@/stores/map'
import { getDrone } from '@/api/api'

const mapStore = useMapStore()
const { focusedDrone, activeDrones } = storeToRefs(mapStore)

const emit = defineEmits(['fly-to'])

function flyToDrone(drone) {
  focusedDrone.value = drone
  const location = mapStore.getFocusedDroneLocation()
  emit('fly-to', location)
}

function showDroneInfo(drone) {
  mapStore.setInfoDrone(drone.serial_number)
}

async function updateDrone(drone) {
  if(!drone.home_position || !drone.pilot_position) {
    const drone_dto = await getDrone(drone.serial_number)
    drone.home_position = drone_dto.home_position
    drone.pilot_position = drone_dto.pilot_position
  }
}
</script>

<style>
@reference "tailwindcss";

.table-container {
  @apply relative max-h-[40vh] overflow-y-auto overflow-x-hidden;
}

thead {
  @apply sticky top-0 bg-white z-10;
}

th {
  @apply text-left py-2 px-3 text-sm font-medium text-gray-600;
}

th:not(:first-child) {
  @apply text-center w-12;
}

tr:not(thead tr) {
  @apply border-b border-gray-100 hover:bg-gray-50;
}

td {
  @apply py-2 px-3 text-center;
}

button {
  @apply p-1 hover:bg-gray-100 rounded-full transition-colors duration-200;
}

input[type='checkbox'] {
  @apply w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500;
}
</style>
