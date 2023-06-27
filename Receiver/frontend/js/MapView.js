import {computed, defineComponent, onMounted, ref, watch} from "vue"
import {CustomControl, GoogleMap} from "vue3-google-map"
import {storeToRefs} from "pinia"
import Drone from "./Drone.js"
import {useStore} from "./Store.js"
import {ActiveDroneList, AllDroneList, DroneInfoPanel, Settings} from "./Components.js"

// Monitor View

const MonitorView = defineComponent({
    name: "MonitorView",
    components: {Drone, Settings, ActiveDroneList, AllDroneList, DroneInfoPanel},
    template: `
        <Settings />
        <ActiveDroneList />
        <AllDroneList />
        <DroneInfoPanel />
        <Drone
            v-for="drone in activeDrones"
            :key="drone.serial_number"
            :drone="drone"
        />
    `, setup() {
        const store = useStore()
        const {activeDrones} = storeToRefs(store)
        const {loadActiveDrones} = store

        onMounted(async () => {
            await loadActiveDrones()
        })

        return {activeDrones}
    }
})

// Replay View

const formatTime = timestamp => new Date(timestamp).toLocaleTimeString()

const ReplayView = defineComponent({
    name: "ReplayView",
    components: {CustomControl, Settings, DroneInfoPanel, Drone},
    template: `
        <Settings />
        <Drone :drone="drone" />
        <DroneInfoPanel :minimal="true" />
        <CustomControl position="TOP_CENTER" class="panel" style="text-align: center;">
            <div class="title">Replay in progress</div>
            <div class="subtitle">{{ drone.serial_number }}</div>
        </CustomControl>
        <CustomControl position="BOTTOM_CENTER" class="panel" style="display: flex; flex-direction: column; align-items: center; width: 50%; padding: 1rem 2.5rem;">
            <div style="width: 100%; display: flex; justify-content: space-between; align-items: start;">
                <span></span>
                <span class="title">Timeline</span>
                <button @click="closeReplay()" title="Close">❌</button>
            </div>
            <div style="font-size: 1rem">
                <button class="button" title="Start" @click="replayIndex = 0">⏮️</button>

                <button v-if="isReplayPlaying" class="button" title="Pause" @click="pauseReplay()">⏸️</button>
                <button v-else class="button" title="Play" @click="playReplay()">▶️</button>

                <button class="button" title="End" @click="replayIndex = maxSteps">⏭️</button>
            </div>
            <div style="width: 100%; display: flex; justify-content: space-between;">
                <span>{{ start }}</span>
                <span>{{ middle }}</span>
                <span>{{ end }}</span>
            </div>
            <input type="range" min="0" :max="maxSteps" step="1" v-model="replayIndex" style="width: 100%;">
            <span style="align-self: start; transform: translateX(-50%); white-space: nowrap;" :style="style">
                {{ current }}
            </span>
        </CustomControl>
    `, setup() {
        const store = useStore()
        const {replayDrone, replayTimeline, replayIndex, isReplayPlaying} = storeToRefs(store)
        const {playReplay, pauseReplay, closeReplay} = store

        const maxSteps = computed(() => replayTimeline.value.length - 1)
        const timeAt = index => formatTime(replayTimeline.value[index].timestamp)
        const start = computed(() => timeAt(0))
        const middle = computed(() => timeAt(Math.floor(maxSteps.value / 2)))
        const end = computed(() => timeAt(maxSteps.value))
        const current = computed(() => timeAt(replayIndex.value))

        const percentage = computed(() => replayIndex.value / maxSteps.value * 100)
        const style = computed(() => ({
            marginLeft: `${percentage.value}%`
        }))
        return {
            drone: replayDrone,
            replayIndex,
            maxSteps,
            start, middle, end, current,
            isReplayPlaying, playReplay, pauseReplay,
            closeReplay,
            style
        }
    }
})

// Map view

const height = window.innerHeight // for some reason, 100% doesn't work on height
export default defineComponent({
    name: "MapView",
    components: {GoogleMap, MonitorView, ReplayView, CustomControl},
    template: `
        <GoogleMap
                v-if="apiKey"
                style="width: 100%; height: ${height}px"
                :api-key="apiKey"
                :center="center"
                :clickableIcons="false"
                :streetViewControl="false"
                :zoom="15"
                :disable-double-click-zoom="true"
                @dragend="untrackDrone()"
                ref="mapRef">
            <ReplayView v-if="isReplayMode"/>
            <MonitorView v-else/>
            <CustomControl position="RIGHT_BOTTOM" class="panel clickable" style="text-align: center;" title="Center to your location">
               <button @click="setLocationAsCenter">📍</button>
            </CustomControl>
        </GoogleMap>
        <div v-else>Loading Google Maps...</div>
        `, setup() {
        // default position is Greenwich observatory
        const center = ref({lat: 51.4778, lng: -0.0014})
        // load your current location (asks for permission)
        const setLocationAsCenter = () => {
            navigator.geolocation.getCurrentPosition(pos => {
                const position = {lat: pos.coords.latitude, lng: pos.coords.longitude}
                center.value = position
                if (mapRef.value?.ready) mapRef.value.map.panTo(position)
            })
        }

        const store = useStore()
        const {trackedDrone, isReplayMode, settings} = storeToRefs(store)
        const {untrackDrone} = store

        // update center when tracked drone changes position
        const mapRef = ref()
        watch(() => trackedDrone.value?.position, position => {
            if (position && mapRef.value?.ready) {
                mapRef.value.map.panTo(position)
            }
        })

        // center location on mount
        onMounted(setLocationAsCenter)

        const apiKey = computed(() => settings.value?.google_maps_api_key)

        return {
            center,
            mapRef,
            apiKey,
            untrackDrone,
            isReplayMode,
            setLocationAsCenter
        }
    }
})
