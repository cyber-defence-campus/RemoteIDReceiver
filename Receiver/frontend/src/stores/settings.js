import { ref } from 'vue'
import { defineStore } from 'pinia'
import { getSettings, postSettings } from '@/api/api'

export const useSettingsStore = defineStore('settings', () => {
  /**
   * server settings are stored here
   *
   * Properties:
   * "interfaces": [],
   */
  const settings = ref({})
  const googleApiKey = ref(null)

  async function loadSettings() {
    settings.value = await getSettings()
  }

  async function updateSettings() {
    settings.value = await postSettings(settings.value)
  }

  return { settings, googleApiKey, loadSettings, updateSettings }
})
