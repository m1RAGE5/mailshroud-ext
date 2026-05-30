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
                    const btnEl = document.createElement("button");
                    btnEl.className = "mailshroud-encrypt-btn";
                    btnEl.textContent = "🔒 Шифрувати";

                    const encryptBtn = $(btnEl);
                    encryptBtn.css({
                        marginLeft: "8px",
                        padding: "10px 20px",
                        background: "#10b981",
                        color: "white",
                        border: "none",
                        borderRadius: "4px",
                        cursor: "pointer",
                        fontSize: "14px",
                        fontWeight: "600",
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

                    sendButton.after(encryptBtn);
                }
            }, 500);
        }

        // 6. Обробник кліку на кнопку шифрування
        async function handleEncryptClick(compose: any) {
            const composeId = compose.id();

            // АЛЬТЕРНАТИВНИЙ СПОСІБ: Прямий збір адрес з DOM-елементів вікна.
            // Це повністю уникає багів бібліотеки gmail-js з фокусом та прихованими полями.
            const recipientsSet = new Set<string>();

            // 1. Шукаємо всі "чіпи" контактів, які Gmail створює при введенні (вони мають атрибут email)
            compose.$el.find("[email]").each(function (
                _index: number,
                element: HTMLElement,
            ) {
                const emailAddr = $(element).attr("email"); // Використовуємо element замість this
                if (emailAddr && emailAddr.includes("@")) {
                    recipientsSet.add(emailAddr.toLowerCase());
                }
            });

            // 2. Додаткова перевірка: шукаємо у прихованих полях вводу (hidden inputs)
            compose.$el.find('input[type="hidden"]').each(function (
                _index: number,
                element: HTMLElement,
            ) {
                const val = $(element).val(); // Використовуємо element замість this
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

            // Видаляємо власну адресу відправника зі списку отримувачів,
            // оскільки ми її і так передаємо окремо як senderEmail
            const finalRecipients = Array.from(recipientsSet).filter(
                (email) => email !== senderEmail.toLowerCase(),
            );

            if (finalRecipients.length === 0) {
                alert("Додайте хоча б одного отримувача перед шифруванням");
                return;
            }

            if (body.includes("-----BEGIN PGP MESSAGE-----")) {
                alert("Лист вже зашифровано");
                return;
            }

            // Відправляємо запит на шифрування в Content Script.
            // Передаємо всіх отримувачів масивом "to" (для PGP цього достатньо)
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

            const btn = compose.$el.find(".mailshroud-encrypt-btn");
            btn.text("⏳ Шифрування...").prop("disabled", true);
        }

        // 7. Слухаємо відповіді від Content Script
        window.addEventListener("message", (event) => {
            // 🔒 БЕЗПЕКА: Перевірка походження
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
                alert(`❌ Помилка шифрування:\n${error}`);
                btn.text("🔒 Шифрувати").prop("disabled", false);
            } else {
                // ⚠️ БЕЗПЕКА: Gmail блокує вставку HTML-рядків (Trusted Types).
                // Тому ми використовуємо нативні DOM-елементи, які не підлягають цим обмеженням.

                // 1. Знаходимо DOM-контейнер тіла листа
                const bodyContainer = compose.$el.find(
                    'div[contenteditable="true"]',
                )[0];

                if (bodyContainer) {
                    // 2. Безпечно очищаємо поточний вміст
                    bodyContainer.textContent = "";

                    // 3. Створюємо елемент <pre> нативно
                    const preElem = document.createElement("pre");
                    preElem.style.whiteSpace = "pre-wrap";
                    preElem.style.fontFamily = "monospace";
                    preElem.style.margin = "0";

                    // 4. Вставляємо текст. Властивість textContent автоматично
                    // зберігає перенесення рядків та безпечно екранує <, >, &
                    preElem.textContent = encrypted;

                    // 5. Вставляємо наш елемент у лист
                    bodyContainer.appendChild(preElem);
                } else {
                    console.error(
                        "[MailShroud] Не знайдено поле вводу для вставки тексту",
                    );
                }
            }
        });

        console.log(
            "[MailShroud] Gmail Bridge initialized successfully (Main World)",
        );
    } catch (err) {
        console.error("[MailShroud] Failed to initialize Gmail Bridge:", err);
    }
});
