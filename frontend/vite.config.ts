import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // @xterm/xterm 6.0.0 ships minified ESM. Disable identifier mangling in
  // Vite/esbuild to avoid the documented production-only double-minification
  // closure bug while preserving whitespace/syntax minification.
  esbuild: {
    minifyIdentifiers: false,
  },
  build: {
    rollupOptions: {
      input: {
        app: "index.html",
        remoteSsh: "remote-ssh.html",
      },
    },
  },
});
