import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "build",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        popup: "popup.html",
        options: "options.html",
        offscreen: "offscreen.html",
        background: "src/background.ts",
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  resolve: {
    dedupe: ["kdbxweb", "hash-wasm"],
  },
});
