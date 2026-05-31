import { defineContentScript, injectScript } from "#imports";
import { messenger } from "~/lib/messaging";
import { sanitizeDecryptedHtml } from "~/lib/security/sanitize";

export default defineContentScript({
    matches: ["*://mail.google.com/*"],
    runAt: "document_start", // ⚠️ КРИТИЧНО: gmail.js вимагає document_start
    async main(ctx) {
        console.log("[MailShroud] Content Script started (Isolated World)");

        // 1. Інжекція gmail-bridge.js у Main World
        try {
            await injectScript("/gmail-bridge.js", { keepInDom: true });
            console.log("[MailShroud] Gmail bridge injected successfully");
        } catch (err) {
            console.error(
                "[MailShroud] Failed to inject gmail-bridge.js:",
                err,
            );
        }

        // 2. Комунікація з Main World (gmail-bridge.ts)
        window.addEventListener("message", async (event) => {
            if (
                event.source !== window ||
                event.origin !== "https://mail.google.com"
            )
                return;

            const { type, payload } = event.data || {};
            if (!type) return;

            if (type === "MAILSHROUD_COMPOSE_READY") {
                console.log(
                    "[MailShroud] Compose window detected:",
                    payload?.id,
                );
            }

            if (type === "MAILSHROUD_ENCRYPT_REQUEST") {
                await handleEncryptRequest(payload);
            }
        });

        // 3. Обробник запиту на шифрування
        async function handleEncryptRequest(payload: any) {
            const { composeId, to, cc, bcc, body, senderEmail } = payload;

            const extractEmails = (recipients: any[]): string[] => {
                if (!recipients || !Array.isArray(recipients)) return [];
                return recipients
                    .map((r: any) => {
                        if (typeof r === "string") return r;
                        return r.email || r.address || null;
                    })
                    .filter(
                        (email: string | null): email is string =>
                            email !== null && email.includes("@"),
                    );
            };

            const recipientEmails = [
                ...extractEmails(to),
                ...extractEmails(cc),
                ...extractEmails(bcc),
            ];

            if (recipientEmails.length === 0) {
                window.postMessage(
                    {
                        type: "MAILSHROUD_ENCRYPT_RESPONSE",
                        payload: {
                            composeId,
                            error: "Не знайдено жодного валідного отримувача",
                        },
                    },
                    "https://mail.google.com",
                );
                return;
            }

            try {
                const plainText = htmlToPlainText(body);

                const result = await messenger.sendMessage("encryptMessage", {
                    text: plainText,
                    recipientEmails,
                    senderEmail,
                });

                window.postMessage(
                    {
                        type: "MAILSHROUD_ENCRYPT_RESPONSE",
                        payload: {
                            composeId,
                            encrypted: result.encrypted,
                        },
                    },
                    "https://mail.google.com",
                );
            } catch (err: any) {
                console.error("[MailShroud] Encryption failed:", err);
                window.postMessage(
                    {
                        type: "MAILSHROUD_ENCRYPT_RESPONSE",
                        payload: {
                            composeId,
                            error: err.message || "Невідома помилка шифрування",
                        },
                    },
                    "https://mail.google.com",
                );
            }
        }

        // 4. Утиліта для конвертації HTML в plain text
        function htmlToPlainText(html: string): string {
            const div = document.createElement("div");
            div.innerHTML = html;
            // innerText автоматично обробляє блокові елементи та прихований контент
            return div.innerText || div.textContent || "";
        }

        // 5. Інжекція стилів для UI (дешифрування)
        const style = document.createElement("style");
        style.textContent = `
      .mailshroud-box { 
        margin: 16px 0; padding: 16px; border: 2px dashed #10b981; 
        border-radius: 8px; background: #f0fdf4; font-family: system-ui, sans-serif; 
      }
      .ms-btn { 
        background: #10b981; color: white; border: none; padding: 10px 20px; 
        border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; 
      }
      .ms-btn:hover { background: #059669; }
      .ms-status { color: #059669; font-weight: 500; }
      .ms-error { color: #dc2626; font-weight: 500; }
      .ms-content { 
        margin-top: 12px; padding-top: 12px; border-top: 1px solid #d1fae5; 
        color: #1f2937; line-height: 1.5; white-space: pre-wrap; word-break: break-word; 
      }
      .ms-content a { color: #2563eb; text-decoration: underline; }
    `;
        document.head.appendChild(style);

        // 6. Логіка пошуку PGP-блоків
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

                        const depth = getDepth(current, root);
                        if (depth > 10) break;

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
                        if (
                            container.closest(
                                '.y2, .aE3, .zA, .xT, [role="row"]',
                            )
                        ) {
                            textNode = walker.nextNode();
                            continue;
                        }

                        if (!container.closest(".a3s, .ii.gt, .adn, .if")) {
                            textNode = walker.nextNode();
                            continue;
                        }

                        processed.add(container);
                        handlePgpContainer(container);
                    }
                }
                textNode = walker.nextNode();
            }
        }

        function getDepth(node: Node, root: Node): number {
            let depth = 0;
            let current: Node | null = node;
            while (current && current !== root) {
                depth++;
                current = current.parentNode;
            }
            return depth;
        }

        function handlePgpContainer(container: HTMLElement) {
            const text = container.textContent || "";
            const match = text.match(PGP_REGEX);
            if (!match) return;

            const armored = match[0];
            const box = document.createElement("div");
            box.className = "mailshroud-box";
            const decryptBtn = document.createElement("button");
            decryptBtn.className = "ms-btn";
            decryptBtn.textContent = "🔒 Розшифрувати лист";
            box.appendChild(decryptBtn);

            container.parentNode?.insertBefore(box, container);
            container.style.display = "none";

            decryptBtn.addEventListener("click", async () => {
                box.textContent = "";
                const statusSpan = document.createElement("span");
                statusSpan.className = "ms-status";
                statusSpan.textContent = "⏳ Розшифровка...";
                box.appendChild(statusSpan);

                try {
                    const res = await messenger.sendMessage(
                        "decryptMessage",
                        armored,
                    );
                    const safeHtml = sanitizeDecryptedHtml(res.data);

                    box.textContent = "";
                    const contentDiv = document.createElement("div");
                    contentDiv.className = "ms-content";
                    contentDiv.innerHTML = safeHtml; // DOMPurify гарантує безпеку
                    box.appendChild(contentDiv);
                } catch (err: any) {
                    box.textContent = "";
                    const errorSpan = document.createElement("span");
                    errorSpan.className = "ms-error";
                    const msg =
                        err?.code === "VAULT_LOCKED"
                            ? "🔒 Vault заблоковано. Розблокуйте в Popup."
                            : err?.message || "Невідома помилка дешифрування";
                    errorSpan.textContent = `❌ ${msg}`;
                    box.appendChild(errorSpan);
                }
            });
        }

        // 7. MutationObserver
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

        // Очищення при знищенні контексту розширення (наприклад, при оновленні)
        ctx.onInvalidated(() => {
            observer.disconnect();
            console.log(
                "[MailShroud] Context invalidated, observer disconnected",
            );
        });
    },
});
