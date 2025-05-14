<template>
  <div class="app flex flex-row h-full">
    <!-- Sidebar: Drone list -->
    <AllDroneListPanel class="animate-margin w-96 bg-white z-10 inline-block" :class="{ '-ml-96': !showAllDrones }" />

    <!-- Main Page-->
    <div class="w-full inline-block relative">
      <!-- Map -->
      <div id="background_map" class="h-full" />

      <!-- Icons -->
      <div class="icons absolute top-0">
        <SettingsPanel class="bg-white" />
        <div
          class="bg-white w-16 h-16 m-4 shadow-xl rounded-full text-center content-center cursor-pointer select-none z-10"
          @click="toggleDroneList">
          <font-awesome-icon :icon="faClockRotateLeft" size="xl" />
        </div>
      </div>

      <!-- Logo -->
      <div class="absolute top-0 right-0">
        <img :src="cydLogo" alt="CYD Logo" class="w-16 h-auto m-4 rounded-lg shadow-xl" />
      </div>

      <!-- Info Panels -->
      <div class="absolute bottom-0">
        <DroneInfoPanel class="m-4 p-4" @fly-to="flyToLocation" />
        <ActiveDoneListPanel v-if="!replayModeIsActive" class="m-4 p-4" @fly-to="flyToLocation" />
        <ReplayControls v-if="replayModeIsActive" class="m-4 p-4" />
      </div>
    </div>
  </div>
</template>

<script setup>
// Vue imports
import { onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'

// Component imports
import SettingsPanel from './map-panels/SettingsPanel.vue'
import ActiveDoneListPanel from './map-panels/ActiveDoneListPanel.vue'
import AllDroneListPanel from './map-panels/AllDroneListPanel.vue'
import DroneInfoPanel from './map-panels/DroneInfoPanel.vue'
import ReplayControls from './map-panels/ReplayControls.vue'

// Store imports
import { useMapStore } from '@/stores/map'
import { useSettingsStore } from '@/stores/settings'

// Map imports
import maplibregl from 'maplibre-gl'
import 'maplibre-gl/dist/maplibre-gl.css'
import { googleProtocol } from 'maplibre-google-maps'

// Icon imports
import { faClockRotateLeft } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
import droneIcon from '../assets/img/drone_128.png'
import markerIconHome from '../assets/img/marker_home.png'
import markerIconPilot from '../assets/img/marker_pilot.png'
import cydLogo from '../assets/img/cyd.jpg'


// Props
const props = defineProps({
  style: {
    type: String,
    default: 'https://demotiles.maplibre.org/style.json',
  },
})


// State
const map = ref(null)
const showAllDrones = ref(false)
const inAnimation = ref(false)

// Store initialization
const mapStore = useMapStore()
const { replayModeIsActive, focusedDrone, infoDrone, activeDrones } = storeToRefs(mapStore)

const infoDronePopup = new maplibregl.Popup({offset: 25, closeButton: false})

// Map initialization
const initializeMap = async () => {
  maplibregl.addProtocol('google', googleProtocol)

  map.value = new maplibregl.Map({
    container: 'background_map',
    style: props.style,
    center: [7.44744, 46.94809],
    zoom: 15,
  })

  // load icons
  const loadedDroneIcon = await map.value.loadImage(droneIcon)
  map.value.addImage('drone-icon', loadedDroneIcon.data)

  const loadedMarkerHomeIcon = await map.value.loadImage(markerIconHome)
  map.value.addImage('marker-home', loadedMarkerHomeIcon.data)

  const loadedMarkerPilotIcon = await map.value.loadImage(markerIconPilot)
  map.value.addImage('marker-pilot', loadedMarkerPilotIcon.data)


  map.value.on('load', () => {
    const path = {
      type: 'geojson',
      data: {
        type: 'FeatureCollection',
        features: [],
      },
    }

    const drones = {
      type: 'geojson',
      data: {
        type: 'FeatureCollection',
        features: [],
      },
    }

    const pilots = {
      type: 'geojson',
      data: {
        type: 'FeatureCollection',
        features: [],
      },
    }

    const homes = {
      type: 'geojson',
      data: {
        type: 'FeatureCollection',
        features: [],
      },
    }

    map.value.addSource('path-source', path)
    map.value.addLayer({
      id: 'drone-paths',
      type: 'line',
      source: 'path-source',
      layout: {
        'line-cap': 'round',
        'line-join': 'round',
      },
      paint: {
        'line-color': '#34a8bf',
        'line-width': 5,
        'line-opacity': 0.8,
      },
    })

    map.value.addSource('drones-source', drones)
    map.value.addLayer({
      id: 'drones',
      type: 'symbol',
      source: 'drones-source',
      layout: {
        'icon-image': 'drone-icon',
        'icon-size': 0.4,
        'icon-allow-overlap': true,
      },
    })

    map.value.addSource('pilots-source', pilots)
    map.value.addLayer({
      id: 'pilots',
      type: 'symbol',
      source: 'pilots-source',
      layout: {
        'icon-image': 'marker-pilot',
        'icon-size': 1,
        'icon-allow-overlap': true,
      },
    })

    map.value.addSource('homes-source', homes)
    map.value.addLayer({
      id: 'homes',
      type: 'symbol',
      source: 'homes-source',
      layout: {
        'icon-image': 'marker-home',
        'icon-size': 1,
        'icon-allow-overlap': true,
      },
    })

    startRenderLoop()
  })

  map.value.on('dragstart', () => {
    focusedDrone.value = null
  })

  map.value.on('click', 'drones', (e) => {
    if (e.features.length > 0) {
      const feature = e.features[0]
      const serialNumber = feature.properties.serialNumber

      mapStore.setInfoDrone(serialNumber)
      const drone = activeDrones.value.find(drone => drone.serial_number === serialNumber)

      const allShown = drone.show_home && drone.show_path && drone.show_pilot

      if (allShown) {
        drone.show_home = false
        drone.show_path = false
        drone.show_pilot = false
      } else {
        drone.show_home = true
        drone.show_path = true
        drone.show_pilot = true
      }
    }
  })

  // Add cursor styling when hovering over drones
  map.value.on('mouseenter', 'drones', () => {
    map.value.getCanvas().style.cursor = 'pointer'
  })

  // Remove cursor styling when hovering over drones
  map.value.on('mouseleave', 'drones', () => {
    map.value.getCanvas().style.cursor = ''
  })
}

// Render loop
const startRenderLoop = () => {
  const render = () => {

    // Center map on focused drone if any
    const focusDroneLocation = mapStore.getFocusedDroneLocation()
    if (focusDroneLocation && !inAnimation.value) {
      map.value.setCenter(focusDroneLocation)
    }

    // Show info drone popup if any
    const infoDroneLocation = mapStore.getInfoDroneLocation()
    if (infoDroneLocation && !inAnimation.value) {
      infoDronePopup.setLngLat(infoDroneLocation)
      infoDronePopup.setText(infoDrone.value.serial_number)
      infoDronePopup.addTo(map.value)
    }

    // Update drone positions
    const strategy = mapStore.getVisualizationStrategy()

    map.value.getSource('path-source').setData(strategy.getPaths())
    map.value.getSource('drones-source').setData(strategy.getDroneFeatures())
    map.value.getSource('pilots-source').setData(strategy.getPilotFeatures())
    map.value.getSource('homes-source').setData(strategy.getHomeFeatures())

    // Request next frame
    setTimeout(() => requestAnimationFrame(render), 10)
  }

  render()
}

// Navigation
const flyToLocation = (coordinates) => {
  inAnimation.value = true
  map.value.flyTo({
    center: coordinates,
    zoom: 18,
    speed: 1.5,
    easing: (t) => t * (2 - t),
  })
  setTimeout(() => {
    inAnimation.value = false
  }, 1000)
}

// UI handlers
const toggleDroneList = () => {
  showAllDrones.value = !showAllDrones.value
}

// Lifecycle hooks
onMounted(async () => {
  map.value = null
  await mapStore.loadActiveDrones()
  initializeMap()
})

// Remove info drone popup when info drone is removed
watch(infoDrone, () => {
  if (!infoDrone.value) {
    infoDronePopup.remove()
  }
})

const settingsStore = useSettingsStore()
const { googleApiKey } = storeToRefs(settingsStore)

watch(googleApiKey, () => {
  if (googleApiKey.value) {
    initializeMap()
  }
})

</script>

<style>
.animate-margin {
  transition: margin-left 100ms ease-out;
}

.app {
  background-color: aqua;
}
</style>
