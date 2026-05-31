import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiPort = Number(env.AEGIS_UI_API_PORT ?? 8787);
  const uiPort = Number(env.AEGIS_UI_PORT ?? 5173);
  const isTauri = !!process.env.TAURI_DEV;

  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: uiPort,
      strictPort: !isTauri,
      allowedHosts: isTauri ? true : [],
      proxy: isTauri
        ? {}
        : {
            "/api": `http://127.0.0.1:${apiPort}`
          }
    },
    preview: {
      host: "127.0.0.1",
      port: uiPort,
      strictPort: !isTauri,
      allowedHosts: isTauri ? true : []
    },
    clearScreen: !isTauri,
    build: {
      target: isTauri ? "chrome105" : "esnext",
      minify: !isTauri ? "esbuild" : false,
      sourcemap: isTauri
    }
  };
});