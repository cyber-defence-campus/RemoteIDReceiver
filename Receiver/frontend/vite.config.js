import { fileURLToPath, URL } from 'node:url'

import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ mode, command }) => {
  // Load env variables
  const env = loadEnv(mode, process.cwd(), '')
  
  // Process command line arguments
  const styleUrl = process.env.npm_config_style_url
  const styleName = process.env.npm_config_style_name
  
  // Apply command line arguments to env
  if (styleUrl) {
    env.VITE_MAP_STYLE_URL = styleUrl
  }
  
  if (styleName) {
    env.VITE_MAP_STYLE = styleName
  }

  return {
    plugins: [
      vue(),
      vueDevTools(),
      tailwindcss(),
    ],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      },
    },
    server: {
      host: '0.0.0.0',
      port: 3000,
      strictPort: true,
    },
    define: {
      // Make env variables available to the app
      'import.meta.env.VITE_MAP_STYLE_URL': JSON.stringify(env.VITE_MAP_STYLE_URL || ''),
      'import.meta.env.VITE_MAP_STYLE': JSON.stringify(env.VITE_MAP_STYLE || ''),
      'import.meta.env.VITE_GOOGLE_API_KEY': JSON.stringify(env.VITE_GOOGLE_API_KEY || ''),
    }
  }
})
