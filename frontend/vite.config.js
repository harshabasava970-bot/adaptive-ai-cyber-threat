import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'https://cyber-threat-api-4gms.onrender.com',
        changeOrigin: true,
        rewrite: (path) => path
      }
    }
  }
})
