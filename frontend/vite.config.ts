import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Fresh, uncommon ports so they don't collide with services already on
    // 8000/5173. Backend API runs on 8791; this dev server on 5891.
    port: 5891,
    proxy: {
      '/api': {
        target: 'http://localhost:8791',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://localhost:8791',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
