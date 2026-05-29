import { defineContentScript, injectScript } from "#imports";
import { messenger } from "~/lib/messaging";
import { sanitizeDecryptedHtml } from "~/lib/security/sanitize";

export default defineContentScript({
    matches: ["*://mail.google.com/*"],
    runAt: "document_idle",
    async main(ctx) {
        console.log("[MailShroud] Content Script started (Isolated World)");

        // 1. Інжекція gmail-bridge.js з обробкою помилок
        try {
            await injectScript("/gmail-bridge.js", { keepInDom: true });
            console.log("[MailShroud] Gmail bridge injected successfully");
        } catch (err) {
            console.error(
                "[MailShroud] Failed to inject gmail-bridge.js:",
                err,
            );
        }

        // 2. Комунікація з Main World
        window.addEventListener("message", (event) => {
            if (event.source !== window) return;
            const { type, payload } = event.data || {};
            if (type === "MAILSHROUD_COMPOSE_READY") {
                console.log(
                    "[MailShroud] Compose window detected:",
                    payload?.id,
                );
            }
        });

        // 3. Інжекція базових стилів для UI
        const style = document.createElement("style");
        style.textContent = `
            .mailshroud-box { margin: 16px 0; padding: 16px; border: 2px dashed #10b981; border-radius: 8px; background: #f0fdf4; font-family: system-ui, sans-serif; }
            .ms-btn { background: #10b981; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; }
            .ms-btn:hover { background: #059669; }
            .ms-status { color: #059669; font-weight: 500; }
            .ms-error { color: #dc2626; font-weight: 500; }
            .ms-content { margin-top: 12px; padding-top: 12px; border-top: 1px solid #d1fae5; color: #1f2937; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
            .ms-content a { color: #2563eb; text-decoration: underline; }
        `;
        document.head.appendChild(style);

        // 4. Логіка пошуку PGP-блоків (залишається без змін)
        const PGP_BEGIN = "-----BEGIN PGP MESSAGE-----";
        const PGP_END = "-----END PGP MESSAGE-----";
        const PGP_REGEX =
            /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/;
        const processed = new WeakSet<HTMLElement>();

        function scanForPgp(root: Node) {
            const walker = document.createTreeWalker(
                root,
                NodeFilter.SHOW_TEXT,
            );
            let textNode: Node | null = walker.nextNode();

            while (textNode) {
                if (textNode.textContent?.includes(PGP_BEGIN)) {
                    let current: Node | null = textNode;
                    let container: HTMLElement | null = null;

                    while (current && current !== root) {
                        const parentEl =
                            current.parentNode as HTMLElement | null;
                        if (!parentEl) break;

                        const parentText = parentEl.textContent || "";
                        if (
                            parentText.includes(PGP_BEGIN) &&
                            parentText.includes(PGP_END)
                        ) {
                            container = parentEl;
                            break;
                        }
                        current = parentEl;
                    }

                    if (container && !processed.has(container)) {
                        processed.add(container);
                        handlePgpContainer(container);
                    }
                }
                textNode = walker.nextNode();
            }
        }

        function handlePgpContainer(container: HTMLElement) {
            const text = container.textContent || "";
            const match = text.match(PGP_REGEX);
            if (!match) return;

            const armored = match[0];
            const box = document.createElement("div");
            box.className = "mailshroud-box";
            box.innerHTML = `<button class="ms-btn">🔒 Розшифрувати лист</button>`;

            container.parentNode?.insertBefore(box, container);
            container.style.display = "none";

            box.querySelector("button")?.addEventListener("click", async () => {
                box.innerHTML = `<span class="ms-status">⏳ Розшифровка...</span>`;
                try {
                    const res = await messenger.sendMessage(
                        "decryptMessage",
                        armored,
                    );
                    const safeHtml = sanitizeDecryptedHtml(res.data);
                    box.innerHTML = `<div class="ms-content">${safeHtml}</div>`;
                } catch (err: any) {
                    const msg =
                        err?.code === "VAULT_LOCKED"
                            ? "🔒 Vault заблоковано. Розблокуйте в Popup."
                            : err?.message || "Невідома помилка дешифрування";
                    box.innerHTML = `<span class="ms-error">❌ ${msg}</span>`;
                }
            });
        }

        // 5. MutationObserver
        const observer = new MutationObserver((mutations) => {
            for (const m of mutations) {
                for (const n of m.addedNodes) {
                    if (n.nodeType === Node.ELEMENT_NODE) {
                        scanForPgp(n);
                    } else if (
                        n.nodeType === Node.TEXT_NODE &&
                        n.parentElement
                    ) {
                        scanForPgp(n.parentElement);
                    }
                }
            }
        });

        const startObserving = () => {
            const target = document.body || document.documentElement;
            observer.observe(target, { childList: true, subtree: true });
            scanForPgp(target);
            console.log("[MailShroud] UI Observer started");
        };

        if (document.body) startObserving();
        else document.addEventListener("DOMContentLoaded", startObserving);
    },
});
