import {computed, ref} from "vue"
import {defineStore} from "pinia"
import * as api from "./Api.js"

const merge = (loaded, stored) => ({
    ...loaded,
    focused: stored.focused,
    blurred: stored.blurred,
    showPath: stored.showPath,
    showPilot: stored.showPilot,
    showHome: stored.showHome,
    history: stored.history,
    flights: stored.flights,
})

const buildLoads = _droneMap => {
    const _activeDrones = ref([])
    const drones = computed(() => [..._droneMap.value.values()])
    const activeDrones = computed(() => drones.value.filter(
        it => _activeDrones.value.includes(it.serial_number)
    ))

    const _load = loaded => {
        const serial_number = loaded.serial_number
        const stored = _droneMap.value.get(serial_number)
        if (stored) {
            _droneMap.value.set(serial_number, merge(loaded, stored))
        } else {
            _droneMap.value.set(serial_number, loaded)
        }
    }

    const loadActiveDrones = async () => {
        const drones = await api.getActiveDrones()
        for (const drone of drones) {
            _load(drone)
        }
        _activeDrones.value = drones.map(it => it.serial_number)
    }

    const loadAllDrones = async () => {
        const drones = await api.getAllDrones()
        for (const drone of drones) {
            _load(drone)
        }
    }

    const updateDrone = drone => {
        const serial_number = drone.serial_number
        const stored = _droneMap.value.get(serial_number)
        if (stored) {
            const merged = merge(drone, stored)
            merged.history.push({
                timestamp: new Date().toISOString(),
                pos: stored.position,
                pilot_pos: stored.pilot_position,
                home_pos: stored.home_position
            })
            _droneMap.value.set(serial_number, merged)
        } else {
            _droneMap.value.set(serial_number, drone)
            _activeDrones.value.push(serial_number)
        }
    }

    return {
        drones, activeDrones,
        loadActiveDrones, loadAllDrones,
        updateDrone,
    }
}

const buildTrack = (_droneMap, _trackedDrone) => {
    const selectDrone = serial_number => {
        const drone = _droneMap.value.get(serial_number)
        const wasFocused = drone && drone.focused
        for (const [key, value] of _droneMap.value) {
            value.focused = wasFocused ? false : key === serial_number
            value.blurred = wasFocused ? false : key !== serial_number
        }
    }

    const trackedDrone = computed(() => _droneMap.value.get(_trackedDrone.value))
    const untrackDrone = () => _trackedDrone.value = undefined
    const trackDrone = serial_number => {
        _trackedDrone.value = serial_number
    }
    return {
        selectDrone, trackedDrone,
        untrackDrone, trackDrone
    }
}

const buildInfo = _droneMap => {
    const _infoDrone = ref()
    const infoDrone = computed(() => _droneMap.value.get(_infoDrone.value))
    const closeInfo = () => _infoDrone.value = undefined
    const showDroneInfo = async serial_number => {
        const drone = _droneMap.value.get(serial_number)
        if (drone) {
            drone.flights = await api.getFlights(serial_number)
            _infoDrone.value = serial_number
        }
    }
    return {
        infoDrone, closeInfo, showDroneInfo
    }
}

const buildToggles = _droneMap => {
    const _toggle = (option, callback) => serial_number => {
        const drone = _droneMap.value.get(serial_number)
        if (drone) {
            drone[option] = !drone[option]
            if (callback) callback(drone)
        }
    }

    const _loadHistory = async serial_number => {
        const history = await api.getHistory(serial_number)
        const drone = _droneMap.value.get(serial_number)
        drone.history = history
    }

    const toggleShowPath = _toggle("showPath", async drone => {
        if (drone.showPath) await _loadHistory(drone.serial_number)
    })
    const toggleShowPilot = _toggle("showPilot")
    const toggleShowHome = _toggle("showHome")

    return {
        toggleShowPath,
        toggleShowPilot,
        toggleShowHome,
    }
}

const buildReplayStore = (_droneMap, _trackedDrone) => {
    const _replayMode = ref(false)
    const _backup = ref()
    const _flight = ref()
    const _replayIndex = ref()
    const _replayDrone = ref()
    const replayDrone = computed(() => _droneMap.value.get(_replayDrone.value))
    const isReplayMode = computed(() => _replayMode.value)

    const replayIndex = computed({
        get: () => _replayIndex.value,
        set: index => {
            const flight = _flight.value
            if (index < 0 || !flight || index >= flight.length) return
            _replayIndex.value = index

            const serial_number = _replayDrone.value
            const drone = _droneMap.value.get(serial_number)
            const timestamp = flight[index]
            drone.position = timestamp.pos
            drone.pilot_position = timestamp.pilot_pos
            drone.history = flight.filter((_, it) => it <= index)
        }
    })
    const replayTimeline = computed(() => _flight.value)
    const replayFlight = async (serial_number, flight_timestamp) => {
        // fetch & validate flight info
        const flight = await api.getFlight(serial_number, flight_timestamp)
        if (!flight || flight.length === 0) return

        // back drone data up to later restore it
        const drone = _droneMap.value.get(serial_number)
        _backup.value = {...drone}

        // configure drone parameters
        _flight.value = flight
        _replayIndex.value = 0
        const start = flight[0]
        drone.position = start.pos
        drone.pilot_position = start.pilot_pos
        drone.showPath = true
        drone.showPilot = true
        drone.showHome = true

        // track drone and activate replay mode
        _trackedDrone.value = serial_number
        _replayDrone.value = serial_number
        _replayMode.value = true
    }

    let timeout;
    const closeReplay = () => {
        // restore backup
        const drone = _backup.value
        _droneMap.value.set(drone.serial_number, drone)
        _trackedDrone.value = undefined
        _replayMode.value = false
        if (timeout) clearTimeout(timeout)
    }

    const _isReplayPlaying = ref(false)
    const isReplayPlaying = computed(() => _isReplayPlaying.value)
    const playReplay = () => {
        _isReplayPlaying.value = true
        if (timeout) clearTimeout(timeout)
        const currentIndex = Number(_replayIndex.value)
        const flightLength = _flight.value.length

        // if we have already reached the end, restart from 0
        if (currentIndex === flightLength - 1) {
            _replayIndex.value = 0
        }

        const handler = () => {
            const nextIndex = Number(_replayIndex.value) + 1
            // if we have reached end, stop playing, otherwise increment
            if (nextIndex >= _flight.value.length) {
                _isReplayPlaying.value = false
            } else if (nextIndex < flightLength) {
                replayIndex.value = nextIndex
                timeout = setTimeout(handler, 1000)
            }
        }
        timeout = setTimeout(handler, 1000)
    }

    const pauseReplay = () => {
        if (timeout) clearTimeout(timeout);
        _isReplayPlaying.value = false
    }

    return {
        replayDrone, replayFlight, closeReplay,
        replayTimeline, replayIndex, isReplayMode,
        isReplayPlaying, playReplay, pauseReplay,
    }
}

const buildSettingsStore = () => {
    const _settings = ref()
    const settings = computed(() => _settings.value)
    const loadSettings = async () => {
        _settings.value = await api.getSettings()
    }

    const updateSettings = async settings => {
        try {
            _settings.value = await api.postSettings(settings)
        } catch (_) {
            // reload settings after an error
            await loadSettings()
        }
    }
    return {
        settings, loadSettings, updateSettings
    }
}

export const useStore = defineStore("droneStore", () => {
    const _droneMap = ref(new Map())
    const _trackedDrone = ref()
    return {
        ...buildLoads(_droneMap),
        ...buildTrack(_droneMap, _trackedDrone),
        ...buildInfo(_droneMap),
        ...buildToggles(_droneMap),
        ...buildReplayStore(_droneMap, _trackedDrone),
        ...buildSettingsStore(),
    }
})
