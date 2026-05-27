import { browser } from "wxt/browser";

let keepAliveInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Тримає Service Worker живим, поки vault unlocked.
 */
export function startKeepAlive(): void {
    if (import.meta.env.FIREFOX) return;
    if (keepAliveInterval !== null) return;

    keepAliveInterval = setInterval(() => {
        // Side-effect: reset SW idle timer
        browser.runtime.getPlatformInfo().catch(() => {});
    }, 20_000);

    if (import.meta.env.DEV) {
        console.log("[MailShroud] Keep-alive started");
    }
}

export function stopKeepAlive(): void {
    if (keepAliveInterval !== null) {
        clearInterval(keepAliveInterval);
        keepAliveInterval = null;
        if (import.meta.env.DEV) {
            console.log("[MailShroud] Keep-alive stopped");
        }
    }
}

export function isKeepAliveRunning(): boolean {
    return keepAliveInterval !== null;
}
