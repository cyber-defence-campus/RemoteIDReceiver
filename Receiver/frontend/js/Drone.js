import {computed, defineComponent} from "vue"
import {CustomMarker, Marker, Polyline} from "vue3-google-map"
import {storeToRefs} from "pinia"
import {DroneInfo} from "./Components.js"
import {useStore} from "./Store.js"

const COLORS = [
    {hex: "#F44336", hue: "295deg"},
    {hex: "#E91E63", hue: "225deg"},
    {hex: "#9C27B0", hue: "195deg"},
    {hex: "#673AB7", hue: "180deg"},
    {hex: "#3F51B5", hue: "175deg"},
    {hex: "#2196F3", hue: "135deg"},
    {hex: "#03A9F4", hue: "150deg"},
    {hex: "#00BCD4", hue: "100deg"},
    {hex: "#4CAF50", hue: "70deg"},
    {hex: "#8BC34A", hue: "30deg"},
    {hex: "#CDDC39", hue: "15deg"},
    {hex: "#FFC107", hue: "0deg"},
    {hex: "#FF9800", hue: "320deg"},
]

const getColorForText = text => {
    let index = 0
    for (let i = 0; i < text.length; ++i) {
        const code = text.charCodeAt(i)
        index += Math.pow(i + 2, code)
        index = index % COLORS.length
    }
    return COLORS[index]
}

export default defineComponent({
    name: "Drone",
    props: {drone: Object},
    components: {CustomMarker, Marker, Polyline, DroneInfo},
    template: `
        <CustomMarker :options="{ position: drone.position, anchorPoint: 'CENTER' }">
          <div style="text-align: center">
            <div 
                v-if="drone.spoofed"
                title="This drone might be spoofed!" 
                style="text-align: left; font-size: 1.5rem; position: relative; z-index: 1000;"
            >⚠️</div>
            <div :style="style">
                <div
                    v-if="!performanceMode"
                    class="drone"
                    :class="{highlight: drone.focused, lowlight: drone.blurred}"
                    :style="{'--size': droneSize, '--color': color.hex, '--hue': color.hue}"
                    @click="selectDrone(drone.serial_number)">
                  <div class="overlay"></div>
                  <img src="/img/body.svg" class="droneBody" />
                  <img src="/img/prop.svg" class="prop prop1" />
                  <img src="/img/prop.svg" class="prop prop2" />
                  <img src="/img/prop.svg" class="prop prop3" />
                  <img src="/img/prop.svg" class="prop prop4" />
                </div>
                <img 
                    v-else 
                    src="/img/drone.png" 
                    :style="{width: droneSize}"
                    :class="{highlight: drone.focused, lowlight: drone.blurred}"
                    @click="selectDrone(drone.serial_number)"
                />
            </div>
            <div class="panel drone-name" :style="{opacity: drone.focused ? 1 : 'calc(2/3)'}">
                <div class="title" :style="{fontSize}">{{ drone.serial_number }}</div>
                <hr v-if="drone.focused">
                <DroneInfo v-if="drone.focused" :drone="drone" />
            </div>
          </div>
        </CustomMarker>
        <Marker v-if="drone.showPilot" :options="{position: drone.pilot_position, label: 'P', title: 'Pilot'}" />
        <Polyline v-if="drone.showPilot" :options="pilotPath" />
        <Marker v-if="drone.showHome" :options="{position: drone.home_position, label: 'H', title: 'Home'}" />
        <Polyline v-if="drone.showPath" :options="flightPath"/>
        `, setup(props) {

        const store = useStore()
        const {settings} = storeToRefs(store)
        const {selectDrone} = store

        const performanceMode = computed(() => settings.value?.performance_mode)
        const size = computed(() => settings.value?.drone_size_in_rem || 5)
        const droneSize = computed(() => `${size.value}rem`)
        const fontSize = computed(() => `${0.1 * size.value + 0.5}rem`)
        const color = computed(() => getColorForText(props.drone.serial_number))

        const flightPath = computed(() => ({
            path: [...props.drone.history.map(it => it.pos), props.drone.position],
            geodesic: true,
            strokeColor: color.value.hex,
            strokeWeight: 3
        }))

        const pilotPath = computed(() => ({
            path: [props.drone.position, props.drone.pilot_position],
            geodesic: true,
            strokeColor: color.value.hex,
            strokeWeight: 2
        }))

        const style = computed(() => ({
            transform: `rotateZ(${props.drone.rotation}deg)`
        }))

        return {
            performanceMode,
            selectDrone,
            droneSize, fontSize,
            flightPath, pilotPath,
            style, color
        }
    }

})
