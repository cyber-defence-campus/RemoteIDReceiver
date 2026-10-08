<template>
  <!-- Settings Panel -->
  <div v-if="open" class="w-96 m-4 p-4 shadow-xl rounded">
    <div>
      <h2 class="inline-block">Settings</h2>
      <button @click="open = false" class="float-right p-2">❌</button>
    </div>

    <div class="mb-8">
      <h3 class="font-bold text-xl">Interfaces</h3>

      <div v-for="iface in interfaces" :key="iface" class="flex flex-row basis-1/2 justify-start">
        <label :for="idFor(iface)" style="justify-self: end">{{ iface }}</label>
        <input :id="idFor(iface)" v-model="settings.interfaces" type="checkbox" :value="iface" />
      </div>
    </div>

    <div class="flex flex-row justify-between mx-16">
      <button @click="reset()">↩️ Reset</button>
      <button @click="updateSettings()">💾 Save</button>
    </div>
  </div>

  <!-- Settings Icon -->
  <div
    v-else
    @click="openSettings"
    class="w-16 h-16 m-4 shadow-xl rounded-full text-center content-center cursor-pointer select-none"
  >
    ⚙️
  </div>
</template>
<script setup>
import { getInterfaces } from '@/api/api'
import { useSettingsStore } from '@/stores/settings'
import { storeToRefs } from 'pinia'
import { ref } from 'vue'
const open = ref(false)
const interfaces = ref([])

const store = useSettingsStore()
const { settings } = storeToRefs(store)
const { loadSettings } = store

async function refreshInterfaces() {
  interfaces.value = await getInterfaces()
}

async function reset() {
  await loadSettings()
  await refreshInterfaces()
}

async function openSettings() {
  open.value = true
  await refreshInterfaces()
}

async function updateSettings() {
  await store.updateSettings()
  open.value = false
}

reset()
const idFor = (iface) => `iface-${iface}`
</script>
<style>
input,
label {
  flex-basis: 50%;
}

input {
  margin-bottom: 0.4rem;
}
</style>
