<template>
  <div class="absolute h-full w-full content-center">
    <div class="flex flex-col items-center content-center">
      <h1 class="text-center text-2xl font-bold">Drone Sniffer Setup</h1>
      <label for="setup-maps-api" class="mt-4">Enter/Paste Google Maps API Key:</label>
      <input
        id="setup-maps-api"
        v-model="localApiKey"
        type="text"
        class="mt-2 border"
      />
      <button
        :disabled="!localApiKey"
        class="button mt-4"
        @click="updateSettings()"
      >
        Setup
      </button>
    </div>
  </div>
</template>

<script setup>
import { useSettingsStore } from '@/stores/settings'
import { storeToRefs } from 'pinia'
import { ref } from 'vue'

const store = useSettingsStore()
const { googleApiKey } = storeToRefs(store)

const localApiKey = ref(null)

function updateSettings() {
  googleApiKey.value = localApiKey.value?.trim()
  
}
</script>
