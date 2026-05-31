import $ from "jquery";
import { defineUnlistedScript } from "#imports";

export default defineUnlistedScript(async () => {
    // 1. Забезпечуємо наявність jQuery у Main World (gmail.js вимагає цього)
    if (!(window as any).jQuery) {
        (window as any).jQuery = $;
        (window as any).$ = $;
    }

    try {
        // 2. Динамічний імпорт Gmail.js
        // @ts-ignore - gmail.js не має повних ES-модульних типів
        const GmailFactory = await import("gmail-js");
        const GmailClass = GmailFactory.default
            ? GmailFactory.default.Gmail
            : (GmailFactory as any).Gmail;
        const gmail = new GmailClass() as any;

        // 3. Map для зберігання compose об'єктів
        const composeMap = new Map<string, any>();

        // 4. Обсервер для нових compose windows
        gmail.observe.on("compose", (compose: any) => {
            const composeId = compose.id();
            composeMap.set(composeId, compose);
            addEncryptButton(compose);
            console.log("[MailShroud] Compose window detected:", composeId);

            // Повідомляємо Content Script про нове вікно
            window.postMessage(
                {
                    type: "MAILSHROUD_COMPOSE_READY",
                    payload: { id: composeId },
                },
                "https://mail.google.com",
            );
        });

        // ✨ ДОДАТКОВА ФУНКЦІЯ: Відображення тимчасового повідомлення над кнопкою
        function showStatus(
            compose: any,
            text: string,
            isError: boolean = false,
        ) {
            const container = compose.$el.find(".mailshroud-btn-container");
            if (!container.length) return;

            // Видаляємо попереднє повідомлення, якщо воно ще активне
            container.find(".mailshroud-status-msg").remove();

            const statusEl = document.createElement("div");
            statusEl.className = "mailshroud-status-msg";
            statusEl.textContent = text;

            const $status = $(statusEl);
            $status.css({
                position: "absolute",
                bottom: "100%",
                left: "50%",
                transform: "translateX(-50%)",
                marginBottom: "8px",
                background: isError ? "#ef4444" : "#10b981",
                color: "white",
                padding: "6px 12px",
                borderRadius: "4px",
                fontSize: "12px",
                fontWeight: "500",
                zIndex: "10000",
                whiteSpace: "nowrap",
                boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                pointerEvents: "none",
            });

            container.append($status);

            // Анімоване зникнення через 2.5 секунди
            setTimeout(() => {
                $status.fadeOut(300, function () {
                    $(this).remove();
                });
            }, 2500);
        }

        // 5. Функція для додавання кнопки шифрування
        function addEncryptButton(compose: any) {
            const composeEl = compose.$el;

            // Затримка, щоб Gmail встиг відмалювати UI
            setTimeout(() => {
                const sendButton = composeEl.find(".gU.Up").first();
                if (
                    sendButton.length &&
                    !composeEl.find(".mailshroud-encrypt-btn").length
                ) {
                    // Створюємо ізольований контейнер-обгортку для кнопки та майбутніх повідомлень
                    const containerEl = document.createElement("div");
                    containerEl.className = "mailshroud-btn-container";
                    containerEl.style.position = "relative";
                    containerEl.style.display = "inline-block";
                    containerEl.style.marginLeft = "8px";
                    containerEl.style.verticalAlign = "middle";

                    const btnEl = document.createElement("button");
                    btnEl.className = "mailshroud-encrypt-btn";
                    btnEl.textContent = "🔒 Шифрувати";

                    const encryptBtn = $(btnEl);
                    encryptBtn.css({
                        padding: "10px 20px",
                        background: "#10b981",
                        color: "white",
                        border: "none",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                        fontWeight: "600",
                        display: "block", // Займає контейнер повністю
                    });

                    encryptBtn.on("mouseenter", function () {
                        $(this).css("background", "#059669");
                    });
                    encryptBtn.on("mouseleave", function () {
                        $(this).css("background", "#10b981");
                    });
                    encryptBtn.on("click", async () => {
                        await handleEncryptClick(compose);
                    });

                    containerEl.appendChild(btnEl);
                    sendButton.after(containerEl);
                }
            }, 500);
        }

        // 6. Обробник кліку на кнопку шифрування
        async function handleEncryptClick(compose: any) {
            const composeId = compose.id();
            const btn = compose.$el.find(".mailshroud-encrypt-btn");

            const recipientsSet = new Set<string>();

            // 1. Шукаємо всі "чіпи" контактів
            compose.$el.find("[email]").each(function (
                _index: number,
                element: HTMLElement,
            ) {
                const emailAddr = $(element).attr("email");
                if (emailAddr && emailAddr.includes("@")) {
                    recipientsSet.add(emailAddr.toLowerCase());
                }
            });

            // 2. Додаткова перевірка у прихованих полях вводу
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

            // Заміна alerts на плавну валідацію в статус-боксах
            if (finalRecipients.length === 0) {
                showStatus(
                    compose,
                    "⚠️ Додайте хоча б одного отримувача",
                    true,
                );
                return;
            }

            // Очищення від HTML-тегів через регулярні вирази для обходу Trusted Types
            const plainTextCheck = body
                .replace(/<[^>]+>/g, "")
                .replace(/&nbsp;/g, " ")
                .trim();

            if (!plainTextCheck) {
                showStatus(
                    compose,
                    "⚠️ Введіть текст листа перед шифруванням",
                    true,
                );
                return;
            }

            if (body.includes("-----BEGIN PGP MESSAGE-----")) {
                showStatus(compose, "⚠️ Лист вже зашифровано", true);
                return;
            }

            // Відправляємо запит на шифрування в Content Script
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

            // ✨ ЗМІНА: Кнопка не змінює текст, але тимчасово вимикається (захист від double-click)
            btn.prop("disabled", true);
            showStatus(compose, "⏳ Шифрування...");
        }

        // 7. Слухаємо відповіді від Content Script
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
                showStatus(compose, `❌ Помилка: ${error}`, true);
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

                    // ✨ ЗМІНА: Показуємо успіх зверху, вмикаємо кнопку назад із початковим текстом
                    showStatus(compose, "✅ Зашифровано успішно!");
                } else {
                    console.error("[MailShroud] Не знайдено поле вводу");
                    showStatus(compose, "❌ Помилка вставки в DOM", true);
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
