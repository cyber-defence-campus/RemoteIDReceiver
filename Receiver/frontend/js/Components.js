import {computed, defineComponent, ref} from "vue"
import {CustomControl} from "vue3-google-map"
import {storeToRefs} from "pinia"
import {useStore} from "./Store.js"
import {getInterfaces} from "./Api.js"

// Active Drone List

const ListEntry = defineComponent({
    name: "ListEntry",
    props: {drone: Object,},
    template: `
        <span :class="{focused: drone.focused}">{{ drone.serial_number }}</span>
        <button @click="toggleTrack" :class="{active: isTracked}" title="Track drone">🎯</button>
        <button @click="showDroneInfo(drone.serial_number)" title="Show Drone Info">📊</button>
        <input v-model="path" type="checkbox" title="Show Flight Path">
        <input v-model="pilot" type="checkbox" title="Show Pilot">
        <input v-model="home" type="checkbox" title="Show Home">
    `, setup(props) {
        const store = useStore()
        const {trackedDrone} = storeToRefs(store)
        const {
            toggleShowPath, toggleShowPilot, toggleShowHome,
            trackDrone, untrackDrone, showDroneInfo
        } = store

        const path = computed({
            get: () => props.drone.showPath,
            set: () => toggleShowPath(props.drone.serial_number)
        })
        const pilot = computed({
            get: () => props.drone.showPilot,
            set: () => toggleShowPilot(props.drone.serial_number)
        })
        const home = computed({
            get: () => props.drone.showHome,
            set: () => toggleShowHome(props.drone.serial_number)
        })

        const isTracked = computed(() => {
            const drone = trackedDrone.value
            return drone && drone.serial_number === props.drone.serial_number
        })

        const toggleTrack = () => {
            if (isTracked.value) {
                untrackDrone()
            } else {
                trackDrone(props.drone.serial_number)
            }
        }

        return {
            path, pilot, home,
            toggleTrack, isTracked,
            showDroneInfo
        }
    }
})

export const ActiveDroneList = defineComponent({
    name: "ActiveDroneList",
    components: {CustomControl, ListEntry},
    template: `
    <CustomControl position="LEFT_BOTTOM" class="panel drone-list scrollable">
        <div class="title">Active Drones</div>
        <div class="table">
            <span class="subtitle">Serial Number</span>
            <span title="Track Drone">🎯</span>
            <span title="Drone Info">📊</span>
            <span title="Show Flight Path">🚁</span>
            <span title="Show Pilot">👨‍✈️</span>
            <span title="Show Home">🏠</span>
            
            <ListEntry 
                v-for="drone in activeDrones" 
                :key="drone.serial_number"
                :drone="drone"
             />
        </div>
    </CustomControl>
    `, setup() {
        const store = useStore()
        const {activeDrones} = storeToRefs(store)
        return {activeDrones}
    }
})

// All Drone List

export const AllDroneList = defineComponent({
    name: "AllDroneList",
    components: {CustomControl},
    template: `
        <CustomControl position="BOTTOM_CENTER" class="panel drone-list scrollable">
            <div class="title clickable" :title="open ? 'Close' : 'Show drones'" @click="toggle">
                All Drones
                {{ open ? "⬇️" : "⬆️" }}
            </div>
            <ul v-if="open">
                <li v-for="drone in drones" @click="selectDrone(drone)">
                    {{ drone.serial_number }}
                </li>
            </ul>
        </CustomControl>
    `, setup() {
        const store = useStore()
        const {drones} = storeToRefs(store)
        const {loadAllDrones, showDroneInfo} = store

        const open = ref(false)
        const selectDrone = drone => {
            open.value = false
            showDroneInfo(drone.serial_number)
        }

        const toggle = async () => {
            const wasOpen = open.value
            open.value = !wasOpen
            if (!wasOpen) await loadAllDrones()
        }

        return {
            open,
            drones,
            selectDrone,
            toggle
        }
    }
})

// Drone Info

const formatTimestamp = timestamp => new Date(timestamp).toLocaleString()

const coordinateToText = decimal => {
    if (!decimal) return ""
    const degrees = Math.round(decimal)
    decimal = (decimal - degrees) * 60
    const minutes = Math.round(decimal)
    decimal = (decimal - minutes) * 60
    const seconds = Math.round(decimal * 10000) / 10000
    return `${degrees}° ${minutes}' ${seconds}''`
}

const positionToText = pos => {
    if (!pos) return "N/A"
    const {lat, lng} = pos
    const latitude = coordinateToText(lat)
    const longitude = coordinateToText(lng)
    return `${latitude}, ${longitude}`
}

const roundIt = val => {
    return `${Math.round(val)}`
}

const LabelAndValue = defineComponent({
    name: "LabelAndValue",
    props: {
        label: String,
        value: String,
    },
    template: `
    <div>{{ label }}</div>
    <div>{{ value }}</div>`
})

const Actions = defineComponent({
    name: "Actions",
    props: {
        drone: Object,
        withInfo: Boolean
    },
    template: `
        <div>Actions</div>
        <div>
            <button @click="toggleTrack" :class="{active: isTracked}" title="Track drone">🎯</button>
            <button v-if="withInfo" @click="showDroneInfo(drone.serial_number)" title="Show Drone Info">📊</button>
        </div>
    `, setup(props) {
        const store = useStore()
        const {trackedDrone} = storeToRefs(store)
        const {trackDrone, untrackDrone, showDroneInfo,} = store

        const isTracked = computed(() => {
            const drone = trackedDrone.value
            return drone && drone.serial_number === props.drone.serial_number
        })

        const toggleTrack = () => {
            if (isTracked.value) {
                untrackDrone()
            } else {
                trackDrone(props.drone.serial_number)
            }
        }

        return {
            isTracked,
            toggleTrack,
            showDroneInfo
        }
    }
})

const Options = defineComponent({
    name: "Options",
    props: {drone: Object},
    template: `
        <div>Options</div>
        <div>
            <button 
                title="Show Flight Path" 
                :class="{active: drone.showPath}" 
                @click="toggleShowPath(drone.serial_number)"
            >🚁</button>
            <button 
                title="Show Pilot" 
                :class="{active: drone.showPilot}" 
                @click="toggleShowPilot(drone.serial_number)"
            >👨‍✈️</button>
            <button 
                title="Show Home" 
                :class="{active: drone.showHome}" 
                @click="toggleShowHome(drone.serial_number)"
            >🏠</button>
        </div>
    `, setup() {
        const store = useStore()
        const {toggleShowPath, toggleShowPilot, toggleShowHome} = store

        return {
            toggleShowPath,
            toggleShowPilot,
            toggleShowHome
        }
    }
})

export const DroneInfo = defineComponent({
    name: "DroneInfo",
    props: {
        drone: Object,
        withInfo: {
            type: Boolean,
            default: true
        }
    },
    components: {LabelAndValue, Actions, Options},
    template: `
        <div class="drone-info">
            <LabelAndValue v-if="drone.position" label="Drone" :value="positionToText(drone.position)"/>
            <LabelAndValue v-if="drone.pilot_position" label="Pilot" :value="positionToText(drone.pilot_position)"/>
            <LabelAndValue v-if="drone.home_position" label="Home" :value="positionToText(drone.home_position)"/>
            <LabelAndValue 
                v-if="drone.altitude || drone.height" 
                label="Altitude / Height" 
                :value="drone.altitude + ' / ' + drone.height"
            />
            <LabelAndValue 
                v-if="drone.x_speed || drone.y_speed || drone.z_speed" 
                label="Speed" 
                :value="'X: ' + drone.x_speed + ', Y: ' + drone.y_speed + ', Z: ' + drone.z_speed"
            />
            <LabelAndValue v-if="drone.rotation" label="Rotation" :value="roundIt(drone.rotation) + '°'"/>
            <Actions :drone="drone" :with-info="withInfo" />
            <Options :drone="drone" />
            <slot />
        </div>
        `, setup() {
        return {positionToText, roundIt}
    }
})

export const DroneInfoPanel = defineComponent({
    name: "DroneInfoPanel",
    components: {CustomControl, DroneInfo},
    props: {
        minimal: {
            type: Boolean,
            default: false
        }
    },
    template: `
        <CustomControl position="RIGHT_TOP" class="panel scrollable" v-if="drone">
            <div style="display: flex; justify-content: space-between; align-items: start;">
                <span class="title">
                    {{ drone.serial_number }}
                </span>
                <button @click="closeInfo()" title="Close">❌</button>
            </div>
            <DroneInfo :drone="drone" :with-info="false" :minimal="minimal">
                <div v-if="!minimal" >Flights</div>
                <ul  v-if="!minimal" class="flight-list">
                    <li v-for="flight of drone.flights">
                        <button 
                            class="button" 
                            title="Replay flight" 
                            @click="replayFlight(drone.serial_number, flight)"
                        >▶️</button>
                        {{ formatTimestamp(flight) }}
                    </li>
                </ul>
            </DroneInfo>
        </CustomControl>
    `, setup() {
        const store = useStore()
        const {infoDrone} = storeToRefs(store)
        const {closeInfo, replayFlight} = store

        return {
            formatTimestamp,
            drone: infoDrone,
            closeInfo,
            replayFlight
        }
    }
})

// Settings

export const Settings = defineComponent({
    name: "Settings",
    components: {CustomControl},
    template: `
        <CustomControl position="LEFT_TOP" class="panel" style="text-align: center;">
            <div class="title clickable" :title="open ? 'Close' : 'Open'" @click="toggle">
                ⚙️ Settings
                {{ open ? "⬆️" : "⬇️" }}
            </div>
            <div v-if="open" style="display: grid; grid-template-columns: repeat(2, 1fr); grid-gap: 0.25rem;">
            
                <label for="google-maps-key">Google Maps API Key:</label>
                <input id="google-maps-key" type="text" v-model="settings.google_maps_api_key">
            
                <label for="activity_offset">Activity Offset (in m):</label>
                <input id="activity_offset" type="number" v-model="settings.activity_offset_in_m" min="1" max="60">
            
                <label for="drone_size">Drone Size (in rem):</label>
                <input id="drone_size" type="range" v-model="settings.drone_size_in_rem" min="1" max="10">
            
                <label for="performance_mode" title="Represses animations & simplifies UI">Performance Mode:</label>
                <input id="performance_mode" type="checkbox" v-model="settings.performance_mode" style="justify-self: start;">
                
                <div class="subtitle">Wi-Fi Sniffing Interfaces</div>
                <div><!--placeholder--></div>
                
                <template v-for="iface in interfaces" :key="iface">
                    <label :for="idFor(iface)" style="justify-self: end;">{{ iface }}</label>
                    <input :id="idFor(iface)" type="checkbox" :value="iface" v-model="settings.interfaces" style="justify-self: start;" >
                </template>

                <button @click="reset">↩️ Reset</button>
                <button @click="save">💾 Save</button>
            </div>
        </CustomControl>
    `, setup() {
        const store = useStore()
        const {settings} = storeToRefs(store)
        const {loadSettings, updateSettings} = store

        const open = ref(false)
        const interfaces = ref([])
        const load = async () => {
            await loadSettings()
            interfaces.value = await getInterfaces()
        }

        const toggle = async () => {
            const wasOpen = open.value
            open.value = !wasOpen
            if (!wasOpen) await load()
        }

        const reset = async () => {
            await load()
        }

        const save = async () => {
            await updateSettings(settings.value)
        }

        const idFor = iface => `iface-${iface}`

        return {
            settings,
            open, toggle,
            reset, save,
            interfaces,
            idFor
        }
    }
})
