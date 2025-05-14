<template>
  <SetupView v-if="!styleUrl"></SetupView>
  <MapView v-else :style="styleUrl"></MapView>
</template>

<script setup>
import SetupView from './components/SetupView.vue'
import MapView from './components/MapView.vue'
import { ref, onMounted, watch, computed } from 'vue'
import { createGoogleStyle } from 'maplibre-google-maps'
import { storeToRefs } from 'pinia'
import { useSettingsStore } from './stores/settings'

const settingsStore = useSettingsStore()
const { googleApiKey } = storeToRefs(settingsStore)

const MAP_STYLES = {
  default: 'https://demotiles.maplibre.org/style.json',
  swiss_satellite: 'https://vectortiles.geo.admin.ch/styles/ch.swisstopo.imagerybasemap.vt/style.json',
  swiss_light: 'https://vectortiles.geo.admin.ch/styles/ch.swisstopo.lightbasemap.vt/style.json',
}

const styleUrl = ref(null)

onMounted(() => {
  const customStyleUrl = import.meta.env.VITE_MAP_STYLE_URL

  // If a style url is provided, use it
  if(customStyleUrl) {
    return styleUrl.value = customStyleUrl
  }

  // If a style provider is provided, use it
  const styleProvider = import.meta.env.VITE_MAP_STYLE
  const staticGoogleApiKey = import.meta.env.VITE_GOOGLE_API_KEY

  // If the style provider is google and the api key is provided, use the google style
  if(styleProvider == 'google' && staticGoogleApiKey) {
    return styleUrl.value = createGoogleStyle('google', 'roadmap', staticGoogleApiKey)
  } else if(styleProvider == 'google' && !staticGoogleApiKey) {
    return 
  }

  // If the style provider is not google, use the default style
  if(MAP_STYLES[styleProvider]  ) {
    return styleUrl.value = MAP_STYLES[styleProvider]
  }

  // If no style provider is provided, use the default style
  return styleUrl.value = MAP_STYLES.default
})

watch(googleApiKey, () => {
  if(googleApiKey.value) {
    styleUrl.value = createGoogleStyle('google', 'roadmap', googleApiKey.value)
  }
})
</script>