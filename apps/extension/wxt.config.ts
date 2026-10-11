import { defineConfig } from "wxt";
import tailwindcss from "@tailwindcss/vite";

// WXT config — MV3 for Chrome, MV2-compatible build for Firefox via -b firefox.
// See docs: https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "Kleidion",
    description:
      "Zero-knowledge password manager — autofill, TOTP, and shared vaults.",
    version: "0.1.0",
    permissions: ["storage", "activeTab", "scripting", "tabs", "alarms"],
    host_permissions: ["https://*/*", "http://localhost/*"],
    browser_specific_settings: {
      gecko: {
        id: "kleidion-extension@kleidion.app",
        data_collection_permissions: { required: ["none"] },
      },
    },
    content_security_policy: {
      // libsodium WASM (base64-embedded) needs wasm-unsafe-eval in MV3.
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
  vite: () => ({
    plugins: [tailwindcss()],
  }),
});
