import type { Message } from "@webext-core/messaging";

/**
 * Результат розблокування vault
 */
export interface UnlockResult {
    success: boolean;
    unlocked: number;
    failed: number;
    failedEmails: string[];
}

/**
 * Параметри для збереження приватного ключа
 */
export interface StorePrivateKeyParams {
    email: string;
    encryptedArmoredKey: string;
    salt: string;
    iv: string;
    masterPassword: string;
    forceOverwrite?: boolean;
}

/**
 * Результат збереження приватного ключа.
 * Повертається з background після успішної валідації.
 */
export interface StorePrivateKeyResult {
    fingerprint: string;
    email: string;
}

/**
 * Параметри для шифрування повідомлення
 */
export interface EncryptMessageParams {
    text: string;
    recipientEmails: string[];
    senderEmail?: string;
}

export interface DecryptMessageResult {
    data: string;
    signaturesValid: boolean[];
    signerEmails: (string | null)[];
}

/**
Результат шифрування повідомлення
*/
export interface EncryptMessageResult {
    encrypted: string;
    signed: boolean;
    signerEmail?: string;
}

/**
 * Протокол повідомлень між Content Script та Background
 * Усі методи з кількома параметрами використовують об'єкт для type-safety
 */
export interface MailShroudMessages {
    storePrivateKey: (
        params: StorePrivateKeyParams,
    ) => Promise<StorePrivateKeyResult>;

    getPublicKey: (email: string) => Promise<string | null>;
    storePublicKey: (params: {
        email: string;
        armoredKey: string;
    }) => Promise<void>;

    unlockVault: (masterPassword: string) => Promise<UnlockResult>;
    lockVault: () => Promise<void>;
    isVaultUnlocked: () => Promise<boolean>;

    decryptMessage: (armoredText: string) => Promise<DecryptMessageResult>;
    encryptMessage: (
        params: EncryptMessageParams,
    ) => Promise<EncryptMessageResult>;
}

export type MailShroudProtocol = MailShroudMessages;
