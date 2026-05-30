import { browser } from "wxt/browser";
import { defineExtensionMessaging } from "@webext-core/messaging";
import type { MailShroudMessages } from "~/lib/types/messages";

// Цей експорт буде використовуватися і в background, і в popup/content
export const messenger = defineExtensionMessaging<MailShroudMessages>();

/**
 * Надсилає повідомлення фоновому скрипту або іншим частинам розширення
 */
export async function sendMessage(type: string, data?: any) {
    return await browser.runtime.sendMessage({ type, data });
}
