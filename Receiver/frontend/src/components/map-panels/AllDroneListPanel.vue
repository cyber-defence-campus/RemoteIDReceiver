<template>
  <div class="p-8 pt-12">
    <h2>All Drones</h2>

    <div class="grid grid-cols-1 gap-4 -ml-4 mt-8">
      <div
        v-for="drone in drones"
        :key="drone.id"
        class="bg-gray-100 p-4 rounded"
        :class="{ active: infoDrone?.sender_id == drone.sender_id}"
      >
        <span class="font-semibold text-xl">{{ drone.sender_id }}</span>

        <button class="float-right p-1" title="Show Drone Info" @click="showInfoDrone(drone.sender_id)">
          📊
        </button>
      </div>
    </div>
  </div>
</template>
<script setup>
import { getAllDrones } from '@/api/api'
import { useMapStore } from '@/stores/map'
import { storeToRefs } from 'pinia'
import { onMounted, ref } from 'vue'

const drones = ref([])

const mapStore = useMapStore()
const { infoDrone } = storeToRefs(mapStore)

onMounted(async () => {
  drones.value = await getAllDrones()
})

const showInfoDrone = (drone) => {
  mapStore.setInfoDrone(drone)
}
</script>
<style>
.active {
  text-decoration: underline;
}
</style>
