import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development (npm run dev) the API runs separately: python app/lab_server.py (port 8000).
// Vite forwards /api to it, so the browser talks to one origin in both setups.
const apiPort = process.env.LAB_PORT ?? "8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: { "/api": { target: `http://127.0.0.1:${apiPort}`, changeOrigin: true } },
  },
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 900 },
});
