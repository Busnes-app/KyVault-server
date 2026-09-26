import { defineConfig } from "vite";

// Content scripts cannot import chunks, so this builds src/content/fill.ts as a
// single IIFE alongside the popup/options/background build in vite.config.ts.
// No `name`: nothing is assigned to the frame's global scope. The outro makes the
// IIFE return probe(), which executeScript({files}) reports as the frame's result.
export default defineConfig({
  build: {
    outDir: "build",
    emptyOutDir: false,
    sourcemap: false,
    lib: {
      entry: "src/content/fill.ts",
      formats: ["iife"],
      name: "unused",
      fileName: () => "content/fill.js",
    },
    minify: false,
    rollupOptions: { treeshake: false, output: { outro: "return probe();" } },
  },
});
