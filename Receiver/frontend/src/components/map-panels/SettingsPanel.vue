<template>
  <!-- Settings Panel -->
  <div v-if="open" class="w-96 m-4 p-4 shadow-xl rounded">
    <div>
      <h2 class="inline-block">Settings</h2>
      <button @click="open = false" class="float-right p-2">❌</button>
    </div>

    <div class="mb-8">
      <h3 class="font-bold text-xl">Wi-Fi interfaces</h3>

      <div v-for="iface in interfaces" :key="iface" class="flex flex-row basis-1/2 justify-start">
        <label :for="idFor(iface)" style="justify-self: end">{{ iface }}</label>
        <input :id="idFor(iface)" v-model="settings.interfaces" type="checkbox" :value="iface" />
      </div>
    </div>

    <div class="mb-8">
      <h3 class="font-bold text-xl">Bluetooth LE adapters</h3>
      <p class="text-sm">Receives ASTM Remote ID BLE advertisements without connecting to devices.</p>

      <div v-for="adapter in bluetoothInterfaces" :key="adapter" class="flex flex-row basis-1/2 justify-start">
        <label :for="idForBluetooth(adapter)" style="justify-self: end">{{ adapter }}</label>
        <input
          :id="idForBluetooth(adapter)"
          v-model="settings.ble_interfaces"
          type="checkbox"
          :value="adapter"
        />
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
    @click="open = true"
    class="w-16 h-16 m-4 shadow-xl rounded-full text-center content-center cursor-pointer select-none"
  >
    ⚙️
  </div>
</template>
<script setup>
import { getBluetoothInterfaces, getInterfaces } from '@/api/api'
import { useSettingsStore } from '@/stores/settings'
import { storeToRefs } from 'pinia'
import { ref } from 'vue'
const open = ref(false)
const interfaces = ref([])
const bluetoothInterfaces = ref([])

const store = useSettingsStore()
const { settings } = storeToRefs(store)
const { loadSettings } = store

async function reset() {
  await loadSettings()
  interfaces.value = await getInterfaces()
  bluetoothInterfaces.value = await getBluetoothInterfaces()
}

async function updateSettings() {
  await store.updateSettings()
  open.value = false
}

reset()
const idFor = (iface) => `iface-${iface}`
const idForBluetooth = (adapter) => `ble-adapter-${adapter}`
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
