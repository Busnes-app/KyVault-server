import { defineConfig } from "vite";

export default defineConfig({
  // kdbxweb's UMD wrapper falls back to Function("return this") when globalThis is
  // missing; it never is here, and web-ext lint flags the dead eval.
  define: { "typeof globalThis": '"object"' },
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
