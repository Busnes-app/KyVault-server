import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { mockApi } from "./mock/api.ts";

export default defineConfig({
  plugins: [react(), ...(process.env.KYVAULT_MOCK_API === "1" ? [mockApi()] : [])],
  server: {
    port: 5878,
    proxy: process.env.KYVAULT_MOCK_API === "1" ? undefined : {
      "/api": {
        target: "http://localhost:5877",
        changeOrigin: true,
      },
      "/auth": {
        target: "http://localhost:5877",
        changeOrigin: true,
      },
      "/scim": {
        target: "http://localhost:5877",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
