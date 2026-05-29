import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
    srcDir: "src",
    modules: ["@wxt-dev/module-svelte"],
    manifest: ({ browser }) => ({
        name: "MailShroud",
        description: "End-to-End Encryption for Gmail via OpenPGP (RFC 9580)",
        version: "1.0.0",

        // ── Top-level icons (для store listings та about:addons) ──
        icons: {
            "16": "/icon/logo-16.png",
            "32": "/icon/logo-32.png",
            "48": "/icon/logo-48.png",
            "128": "/icon/logo-128.png",
        },

        // ── Permissions ────────────────────────────────────────
        permissions: [
            "alarms", // Auto-lock timer
            "storage", // IndexedDB wrapper + lockout state
            "scripting", // Programmatic content script injection
            "activeTab", // Temporary access to current tab
        ],

        // ── Host Permissions (Gmail only) ──────────────────────
        host_permissions: ["*://mail.google.com/*", "*://*.gmail.com/*"],

        // ── Toolbar Action ─────────────────────────────────────
        action: {
            default_title: "MailShroud",
            default_icon: {
                "16": "/icon/logo-16.png",
                "32": "/icon/logo-32.png",
                "48": "/icon/logo-48.png",
            },
        },

        // ── Content Security Policy ────────────────────────────
        // 'wasm-unsafe-eval' потрібен для OpenPGP.js v6 (Argon2 S2K via WASM)
        // @see https://github.com/openpgpjs/openpgpjs#platform-support
        content_security_policy: {
            extension_pages:
                "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
        },

        // ── Web Accessible Resources (для OpenPGP.js WASM) ────
        web_accessible_resources: [
            {
                resources: ["gmail-bridge.js"],
                matches: ["*://mail.google.com/*", "*://*.gmail.com/*"],
            },
        ],
    }),
    // ── Vite Configuration ─────────────────────────────────────
    vite: () => ({
        build: {
            // OpenPGP.js має великий bundle — збільшуємо chunk size warning limit
            chunkSizeWarningLimit: 1000,
        },
    }),
});
