<template>
  <!-- Settings Panel -->
  <div class="bg-white m-4 p-4 shadow-xl rounded">
    <!-- Header -->
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-lg font-semibold">Drone Replay</h2>
      <button @click="close()" class="p-2 hover:bg-gray-100 rounded-full transition-colors">
        ❌
      </button>
    </div>

    <!-- Timeline Slider -->
    <div class="mb-4">
      <input
        type="range"
        min="0"
        :max="replayLength - 1"
        v-model="replayTimeStep"
        class="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
      />
    </div>

    <!-- Playback Controls -->
    <div class="flex justify-between gap-2">
      <button @click="goToStep(0)" class="control-button">
        <font-awesome-icon :icon="faBackwardFast" />
      </button>

      <button @click="goToStep(replayTimeStep - 1)" class="control-button">
        <font-awesome-icon :icon="faBackwardStep" />
      </button>

      <button @click="play" class="control-button">
        <font-awesome-icon :icon="faPlay" />
      </button>

      <button @click="goToStep(replayTimeStep + 1)" class="control-button">
        <font-awesome-icon :icon="faForwardStep" />
      </button>

      <button @click="goToStep(replayLength)" class="control-button">
        <font-awesome-icon :icon="faForwardFast" />
      </button>
    </div>
  </div>
</template>

<script setup>
import {
  faPlay,
  faBackwardStep,
  faForwardStep,
  faBackwardFast,
  faForwardFast,
} from '@fortawesome/free-solid-svg-icons'
import { storeToRefs } from 'pinia'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
import { useMapStore } from '@/stores/map'

// Store initialization
const mapStore = useMapStore()

// Store refs
const { replayTimeStep, replayLength, replayPath, infoDrone, focusedDrone } = storeToRefs(mapStore)

// Playback state
let playTimeout = null

/**
 * Handles the play functionality with proper timing between steps
 */
function play() {
  if (playTimeout) clearTimeout(playTimeout)
  if (replayTimeStep.value >= replayLength.value) return

  replayTimeStep.value += 1

  if (replayTimeStep.value + 1 >= replayLength.value) return

  const currentPosition = replayPath.value[replayTimeStep.value]
  const nextPosition = replayPath.value[replayTimeStep.value + 1]

  const currentMS = new Date(currentPosition.timestamp).getTime()
  const nextMS = new Date(nextPosition.timestamp).getTime()
  const timeDifferenceMS = nextMS - currentMS

  playTimeout = setTimeout(play, timeDifferenceMS)
}

/**
 * Navigates to a specific step in the replay
 * @param {number} step - The step to navigate to
 * @param {boolean} cancelPlay - Whether to cancel current playback
 */
function goToStep(step, cancelPlay = true) {
  if (cancelPlay && playTimeout) clearTimeout(playTimeout)
  if (step < 0) step = 0
  if (step >= replayLength.value) step = replayLength.value - 1

  replayTimeStep.value = step
}

/**
 * Closes the replay panel and resets the state
 */
function close() {
  mapStore.setReplayPath(null, [])
  infoDrone.value = null
  focusedDrone.value = null
}
</script>

<style>
@reference 'tailwindcss';

.control-button {
  @apply bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded transition-colors;
}
</style>
