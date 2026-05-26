import type { Message } from "@webext-core/messaging";

/**
 * Протокол повідомлень між Content Script та Background
 * Ключі - це типи повідомлень, значення - тип даних (data payload)
 * Для методів з return value використовується функціональний синтаксис
 */
export interface MailShroudMessages {
  decryptMessage: (armoredText: string) => string;
  encryptMessage: (text: string, recipientEmails: string[]) => string;
  unlockVault: (masterPassword: string) => boolean;
  lockVault: () => void;
  storePrivateKey: (
    email: string,
    encryptedArmoredKey: string,
    salt: string,
    iv: string,
  ) => void;
  getPublicKey: (email: string) => string | null;
  storePublicKey: (email: string, armoredKey: string) => void;
  isVaultUnlocked: () => boolean;
}

/**
 * Alias для сумісності (якщо використовується в інших місцях)
 */
export type MailShroudProtocol = MailShroudMessages;
