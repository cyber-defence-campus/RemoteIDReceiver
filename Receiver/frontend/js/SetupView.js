import {defineComponent, ref} from "vue"
import {storeToRefs} from "pinia"
import {useStore} from "./Store.js"

export default defineComponent({
    name: "SetupView",
    template: `
        <div style="width: 100vw; height: 100vh; display: flex; justify-content: center; align-items: center; flex-direction: column;">
            <h1>DeFli RiD Drone Detetction Setup</h1>
            <label for="setup-maps-api">Enter/Paste Google Maps API Key:</label>
            <input id="setup-maps-api" type="text" v-model="apiKey">
            <button style="margin: 0.5rem;" :disabled="!apiKey" @click="setup">Setup</button>
        </div>
    `, setup() {
        const apiKey = ref("")
        const store = useStore()
        const {settings} = storeToRefs(store)
        const {updateSettings} = store

        const setup = async () => {
            await updateSettings({
                ...settings.value,
                google_maps_api_key: apiKey.value.trim()
            })
        }

        return {apiKey, setup}
    }
})
