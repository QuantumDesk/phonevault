import { defineConfig } from "vite";
// @ts-expect-error type error without @types/node package
import process from "node:process";
const host = process.env.TAURI_DEV_HOST;

// Tauri dev/build: keep Rust errors on screen, serve on the fixed port Tauri expects, and don't watch src-tauri.
export default defineConfig(() => ({
  clearScreen: false,
  // WalletConnect Pay is not used: WalletKit gets a stub that reports it unavailable (no wasm, no API).
  resolve: { alias: { "@walletconnect/pay": decodeURIComponent(new URL("./src/wc-pay-stub.ts", import.meta.url).pathname) } },
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
}));
