import { browser } from "wxt/browser";

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

/**
 * Інтервал keep-alive для Service Worker.
 *
 * Chrome вбиває SW через 30 секунд idle (TTL).
 * Ми викликаємо browser.runtime.getPlatformInfo() кожні 20 секунд,
 * що reset-ить idle timer і дає 10 секунд запасу.
 *
 * @see https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers#keep_a_service_worker_alive_until_a_long-running_operation_is_finished
 */
const KEEP_ALIVE_INTERVAL_MS = 20_000;

// ─────────────────────────────────────────────────────────────
//  State
// ─────────────────────────────────────────────────────────────

let keepAliveInterval: ReturnType<typeof setInterval> | null = null;

// ─────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────

/**
 * Запускає keep-alive механізм для Service Worker.
 * Ігнорується в Firefox (не має такої проблеми з SW termination).
 * Безпечний для повторних викликів — не створює дублікати інтервалів.
 */
export function startKeepAlive(): void {
    // Firefox не має проблеми з SW termination як Chromium
    if (import.meta.env.FIREFOX) return;

    // Захист від дублювання
    if (keepAliveInterval !== null) return;

    keepAliveInterval = setInterval(() => {
        // Side-effect: browser.runtime.getPlatformInfo() reset-ить SW idle timer
        browser.runtime.getPlatformInfo().catch((err) => {
            if (import.meta.env.DEV) {
                console.warn("[MailShroud] Keep-alive ping failed:", err);
            }
        });
    }, KEEP_ALIVE_INTERVAL_MS);

    if (import.meta.env.DEV) {
        console.log(
            "[MailShroud] Keep-alive started (interval:",
            KEEP_ALIVE_INTERVAL_MS,
            "ms)",
        );
    }
}

/**
 * Зупиняє keep-alive механізм.
 * Безпечний для виклику коли keep-alive вже зупинений.
 */
export function stopKeepAlive(): void {
    if (keepAliveInterval === null) return;

    clearInterval(keepAliveInterval);
    keepAliveInterval = null;

    if (import.meta.env.DEV) {
        console.log("[MailShroud] Keep-alive stopped");
    }
}
