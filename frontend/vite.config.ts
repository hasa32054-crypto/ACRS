/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { target: "es2020", sourcemap: false },
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8000", "/ws": { target: "ws://localhost:8000", ws: true } },
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
