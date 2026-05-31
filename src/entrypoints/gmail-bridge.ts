import $ from "jquery";
import { defineUnlistedScript } from "#imports";

// Допоміжна функція для створення SVG-вузлів (повністю обходить Trusted Types)
function createSvgNode(tag: string, attrs: Record<string, string>): SVGElement {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const key in attrs) {
        el.setAttribute(key, attrs[key]);
    }
    return el;
}

// Фабрика для чистого програмного збирання іконок без string-парсерів
function getStatusIcon(
    type: "success" | "error" | "warn" | "loading",
): SVGElement {
    const svg = createSvgNode("svg", {
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": type === "success" ? "3" : "2.5",
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
        style: "margin-right: 6px; width: 14px; height: 14px; flex-shrink: 0;",
    });

    if (type === "success") {
        svg.appendChild(
            createSvgNode("polyline", { points: "20 6 9 17 4 12" }),
        );
    } else if (type === "error") {
        svg.appendChild(
            createSvgNode("circle", { cx: "12", cy: "12", r: "10" }),
        );
        svg.appendChild(
            createSvgNode("line", { x1: "15", y1: "9", x2: "9", y2: "15" }),
        );
        svg.appendChild(
            createSvgNode("line", { x1: "9", y1: "9", x2: "15", y2: "15" }),
        );
    } else if (type === "warn") {
        svg.appendChild(
            createSvgNode("path", {
                d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z",
            }),
        );
        svg.appendChild(
            createSvgNode("line", { x1: "12", y1: "9", x2: "12", y2: "13" }),
        );
        svg.appendChild(
            createSvgNode("line", {
                x1: "12",
                y1: "17",
                x2: "12.01",
                y2: "17",
            }),
        );
    } else if (type === "loading") {
        svg.appendChild(
            createSvgNode("circle", {
                cx: "12",
                cy: "12",
                r: "10",
                "stroke-dasharray": "32",
                "stroke-dashoffset": "12",
            }),
        );
        svg.appendChild(
            createSvgNode("animateTransform", {
                attributeName: "transform",
                type: "rotate",
                from: "0 12 12",
                to: "360 12 12",
                dur: "1s",
                repeatCount: "indefinite",
            }),
        );
    }
    return svg;
}

const bgColors: Record<string, string> = {
    success: "#10b981",
    error: "#ef4444",
    warn: "#f59e0b",
    loading: "#3b82f6",
};

export default defineUnlistedScript(async () => {
    if (!(window as any).jQuery) {
        (window as any).jQuery = $;
        (window as any).$ = $;
    }

    try {
        // @ts-ignore
        const GmailFactory = await import("gmail-js");
        const GmailClass = GmailFactory.default
            ? GmailFactory.default.Gmail
            : (GmailFactory as any).Gmail;
        const gmail = new GmailClass() as any;

        const composeMap = new Map<string, any>();

        gmail.observe.on("compose", (compose: any) => {
            const composeId = compose.id();
            composeMap.set(composeId, compose);
            addEncryptButton(compose);
            console.log("[MailShroud] Compose window detected:", composeId);

            window.postMessage(
                {
                    type: "MAILSHROUD_COMPOSE_READY",
                    payload: { id: composeId },
                },
                "https://mail.google.com",
            );
        });

        function showStatus(
            compose: any,
            text: string,
            type: "success" | "error" | "warn" | "loading",
        ) {
            const container = compose.$el.find(".mailshroud-btn-container");
            if (!container.length) return;

            container.find(".mailshroud-status-msg").remove();

            const statusEl = document.createElement("div");
            statusEl.className = "mailshroud-status-msg";

            // Безпечна інжекція іконок та тексту через дерево DOM-нод (Trusted Types Friendly)
            statusEl.appendChild(getStatusIcon(type));
            statusEl.appendChild(document.createTextNode(text));

            const $status = $(statusEl);
            $status.css({
                position: "absolute",
                bottom: "100%",
                left: "50%",
                transform: "translateX(-50%)",
                marginBottom: "8px",
                background: bgColors[type],
                color: "white",
                padding: "6px 12px",
                borderRadius: "4px",
                fontSize: "12px",
                fontWeight: "500",
                zIndex: "10000",
                whiteSpace: "nowrap",
                boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                pointerEvents: "none",
                display: "flex",
                alignItems: "center",
            });

            container.append($status);

            setTimeout(() => {
                $status.fadeOut(300, function () {
                    $(this).remove();
                });
            }, 2500);
        }

        function addEncryptButton(compose: any) {
            const composeEl = compose.$el;

            setTimeout(() => {
                const sendButton = composeEl.find(".gU.Up").first();
                if (
                    sendButton.length &&
                    !composeEl.find(".mailshroud-encrypt-btn").length
                ) {
                    const containerEl = document.createElement("div");
                    containerEl.className = "mailshroud-btn-container";
                    containerEl.style.position = "relative";
                    containerEl.style.display = "inline-block";
                    containerEl.style.marginLeft = "8px";
                    containerEl.style.verticalAlign = "middle";

                    const btnEl = document.createElement("button");
                    btnEl.className = "mailshroud-encrypt-btn";
                    btnEl.textContent = "Шифрувати";

                    const encryptBtn = $(btnEl);
                    encryptBtn.css({
                        padding: "9px 20px",
                        background: "#0db87f",
                        color: "white",
                        border: "none",
                        borderRadius: "18px",
                        cursor: "pointer",
                        fontSize: "14px",
                        fontWeight: "500",
                        display: "block",
                    });

                    encryptBtn.on("mouseenter", function () {
                        $(this).css("background", "#33bf90");
                        $(this).css(
                            "box-shadow",
                            "0 1px 2px 0 rgba(26, 232, 156, 0.45), 0 1px 3px 1px rgba(26, 232, 156, 0.3)",
                        );
                    });
                    encryptBtn.on("mouseleave", function () {
                        $(this).css("background", "#0db87f");
                        $(this).css("box-shadow", "none");
                    });
                    encryptBtn.on("click", async () => {
                        await handleEncryptClick(compose);
                    });

                    containerEl.appendChild(btnEl);
                    sendButton.after(containerEl);
                }
            }, 500);
        }

        async function handleEncryptClick(compose: any) {
            const composeId = compose.id();
            const btn = compose.$el.find(".mailshroud-encrypt-btn");
            const recipientsSet = new Set<string>();

            compose.$el.find("[email]").each(function (
                _index: number,
                element: HTMLElement,
            ) {
                const emailAddr = $(element).attr("email");
                if (emailAddr && emailAddr.includes("@")) {
                    recipientsSet.add(emailAddr.toLowerCase());
                }
            });

            compose.$el.find('input[type="hidden"]').each(function (
                _index: number,
                element: HTMLElement,
            ) {
                const val = $(element).val();
                if (typeof val === "string" && val.includes("@")) {
                    const match = val.match(/<([^>]+)>/);
                    const emailAddr = match ? match[1] : val;
                    if (emailAddr.includes("@")) {
                        recipientsSet.add(emailAddr.toLowerCase().trim());
                    }
                }
            });

            const body = compose.body() || "";
            const senderEmail = gmail.get.user_email() || "";
            const finalRecipients = Array.from(recipientsSet).filter(
                (email) => email !== senderEmail.toLowerCase(),
            );

            if (finalRecipients.length === 0) {
                showStatus(compose, "Додайте хоча б одного одержувача", "warn");
                return;
            }

            const plainTextCheck = body
                .replace(/<[^>]+>/g, "")
                .replace(/&nbsp;/g, " ")
                .trim();
            if (!plainTextCheck) {
                showStatus(
                    compose,
                    "Введіть текст листа перед шифруванням",
                    "warn",
                );
                return;
            }

            if (body.includes("-----BEGIN PGP MESSAGE-----")) {
                showStatus(compose, "Лист вже зашифровано", "warn");
                return;
            }

            window.postMessage(
                {
                    type: "MAILSHROUD_ENCRYPT_REQUEST",
                    payload: {
                        composeId,
                        to: finalRecipients,
                        cc: [],
                        bcc: [],
                        body,
                        senderEmail,
                    },
                },
                "https://mail.google.com",
            );

            btn.prop("disabled", true);
            showStatus(compose, "Шифрування...", "loading");
        }

        window.addEventListener("message", (event) => {
            if (
                event.source !== window ||
                event.origin !== "https://mail.google.com"
            )
                return;

            const { type, payload } = event.data || {};
            if (type !== "MAILSHROUD_ENCRYPT_RESPONSE") return;

            const { composeId, encrypted, error } = payload;
            const compose = composeMap.get(composeId);
            if (!compose) return;

            const btn = compose.$el.find(".mailshroud-encrypt-btn");

            if (error) {
                showStatus(compose, `Помилка: ${error}`, "error");
                btn.prop("disabled", false);
            } else {
                const bodyContainer = compose.$el.find(
                    'div[contenteditable="true"]',
                )[0];

                if (bodyContainer) {
                    bodyContainer.textContent = "";

                    const preElem = document.createElement("pre");
                    preElem.style.whiteSpace = "pre-wrap";
                    preElem.style.fontFamily = "monospace";
                    preElem.style.margin = "0";
                    preElem.textContent = encrypted;

                    bodyContainer.appendChild(preElem);
                    showStatus(compose, "Зашифровано успішно!", "success");
                } else {
                    console.error("[MailShroud] Не знайдено поле вводу");
                    showStatus(compose, "Помилка вставки в DOM", "error");
                }
                btn.prop("disabled", false);
            }
        });

        console.log(
            "[MailShroud] Gmail Bridge initialized successfully (Main World)",
        );
    } catch (err) {
        console.error("[MailShroud] Failed to initialize Gmail Bridge:", err);
    }
});
