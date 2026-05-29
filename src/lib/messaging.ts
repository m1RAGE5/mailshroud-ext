import { defineExtensionMessaging } from "@webext-core/messaging";
import type { MailShroudMessages } from "~/lib/types/messages";

// Цей експорт буде використовуватися і в background, і в popup/content
export const messenger = defineExtensionMessaging<MailShroudMessages>();
