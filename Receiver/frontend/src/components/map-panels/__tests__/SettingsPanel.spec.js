import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineStore } from 'pinia'
import { ref } from 'vue'

const getInterfaces = vi.fn()

vi.mock('@/api/api', () => ({
  getInterfaces: (...args) => getInterfaces(...args),
}))

vi.mock('@/stores/settings', () => {
  const useSettingsStore = defineStore('settings', () => {
    const settings = ref({ interfaces: [] })
    const loadSettings = vi.fn(async () => {})
    const updateSettings = vi.fn(async () => {})
    return { settings, loadSettings, updateSettings }
  })
  return { useSettingsStore }
})

import SettingsPanel from '../SettingsPanel.vue'

describe('SettingsPanel', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    getInterfaces.mockReset()
    getInterfaces.mockResolvedValue(['wlan0'])
  })

  it('refreshes the interface list when the settings panel is opened', async () => {
    const wrapper = mount(SettingsPanel)
    await flushPromises()
    expect(getInterfaces).toHaveBeenCalledTimes(1) // initial reset()

    getInterfaces.mockResolvedValueOnce(['wlan0', 'wlan1'])
    await wrapper.find('.cursor-pointer').trigger('click')
    await flushPromises()

    expect(getInterfaces).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('wlan1')
  })
})
