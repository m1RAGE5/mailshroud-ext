import $ from "jquery";

export default defineUnlistedScript(async () => {
    // 1. Спочатку забезпечуємо наявність jQuery у Main World
    if (!(window as any).jQuery) {
        (window as any).jQuery = $;
        (window as any).$ = $;
    }

    try {
        // 2. Динамічний імпорт Gmail.js ПІСЛЯ jQuery
        // Це вирішує проблему hoisting-у в ES модулях
        // @ts-ignore - gmail.d.ts не є ES-модулем
        const GmailFactory = await import("gmail-js");

        // Залежно від налаштувань Vite об'єкт може бути у default
        const GmailClass = GmailFactory.default
            ? GmailFactory.default.Gmail
            : (GmailFactory as any).Gmail;
        const gmail = new GmailClass() as any;

        // 3. Реєструємо обсервери
        gmail.observe.on("view_email", (email: any) => {
            window.postMessage(
                { type: "MAILSHROUD_EMAIL_VIEW", payload: { id: email.id } },
                "*",
            );
        });

        gmail.observe.on("compose", (compose: any) => {
            window.postMessage(
                {
                    type: "MAILSHROUD_COMPOSE_READY",
                    payload: { id: compose.id },
                },
                "*",
            );
        });

        console.log(
            "[MailShroud] Gmail Bridge initialized successfully (Main World)",
        );
    } catch (err) {
        console.error("[MailShroud] Failed to initialize Gmail Bridge:", err);
    }
});
