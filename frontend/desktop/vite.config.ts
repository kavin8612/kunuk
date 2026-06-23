import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Configurazione Vite per il guscio Tauri (porta fissa: tauri.conf.json la referenzia
// come devUrl; clearScreen disattivato per non perdere i log di `cargo`).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
});
