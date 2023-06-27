import {computed, defineComponent, onMounted} from "vue"
import {storeToRefs} from "pinia"
import {useStore} from "./Store.js"
import {initWebSocket} from "./Api.js"
import MapView from "./MapView.js"
import SetupView from "./SetupView.js"

export default defineComponent({
    components: {MapView, SetupView},
    template: `
        <div v-if="!isReady">Loading...</div>
        <MapView v-else-if="isSetUp"/>
        <SetupView v-else/>
    `, setup() {
        const store = useStore()
        const {settings} = storeToRefs(store)
        const {loadSettings} = store
        const isReady = computed(() => Boolean(settings.value))
        const isSetUp = computed(() => Boolean(settings.value?.google_maps_api_key?.trim()))

        // load api key on mount & initialize websockets
        onMounted(async () => {
            await loadSettings()
            initWebSocket()
        })

        return {isReady, isSetUp}
    }
})
