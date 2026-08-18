import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri sets this when doing mobile/remote dev; harmless otherwise.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],

  // Tauri owns the terminal output, don't let Vite wipe it.
  clearScreen: false,

  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },

  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      // Rust sources are watched by cargo, not Vite.
      ignored: ["**/src-tauri/**"],
    },
  },

  // WebView2 on Windows / WKWebView on macOS both handle modern output fine.
  // Minification is left at Vite 8's default (oxc); naming esbuild here would
  // pull in a dependency it no longer bundles.
  build: {
    target: "chrome110",
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
  },
});
