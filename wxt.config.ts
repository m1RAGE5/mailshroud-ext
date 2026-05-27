import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
    srcDir: "src",
    modules: ["@wxt-dev/module-svelte"],
    manifest: {
        name: "MailShroud",
        description: "E2EE for Gmail via OpenPGP",
        permissions: ["alarms", "storage", "activeTab"],
        host_permissions: ["*://mail.google.com/*", "*://gmail.com/*"],
        content_security_policy: {
            extension_pages:
                "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
        },
    },
});
