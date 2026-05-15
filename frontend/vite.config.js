import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [
    tailwindcss(),
    react(),
  ],
  server: {
    proxy: {
      '/api': {
        target: 'https://localhost:5000',
        secure: false,
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'https://localhost:5000',
        secure: false,
        changeOrigin: true,
        ws: true,
      }
    }
  }
})
