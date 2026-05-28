// ─────────────────────────────────────────────────────────────
//  Result Types
// ─────────────────────────────────────────────────────────────

/** Результат розблокування vault */
export interface UnlockResult {
    success: boolean;
    unlocked: number;
    failed: number;
    failedEmails: string[];
}

/** Результат збереження приватного ключа */
export interface StorePrivateKeyResult {
    fingerprint: string;
    email: string;
}

/** Результат генерації нової пари ключів */
export interface GenerateKeyPairResult {
    privateKeyFingerprint: string;
    publicKeyArmored: string;
    revocationCertificate: string;
    email: string;
}

/** Результат шифрування повідомлення */
export interface EncryptMessageResult {
    encrypted: string;
    signed: boolean;
    signerEmail?: string;
}

/** Результат дешифрування повідомлення */
export interface DecryptMessageResult {
    data: string;
    signaturesValid: boolean[];
    signerEmails: (string | null)[];
}

/** Коротка інформація про ключ (для UI списків) */
export interface KeyInfo {
    email: string;
    fingerprint: string;
    createdAt: number;
    source?: string;
    verified?: boolean;
}

// ─────────────────────────────────────────────────────────────
//  Request Parameter Types
// ─────────────────────────────────────────────────────────────

/** Параметри для збереження приватного ключа */
export interface StorePrivateKeyParams {
    email: string;
    encryptedArmoredKey: string;
    salt: string;
    iv: string;
    masterPassword: string;
    forceOverwrite?: boolean;
}

/** Параметри для шифрування повідомлення */
export interface EncryptMessageParams {
    text: string;
    recipientEmails: string[];
    senderEmail?: string;
}

/** Параметри для генерації нової пари ключів */
export interface GenerateKeyPairParams {
    email: string;
    name?: string;
    masterPassword: string;
}

/** Параметри для зміни master password */
export interface ChangeMasterPasswordParams {
    currentPassword: string;
    newPassword: string;
}

/** Параметри для збереження публічного ключа */
export interface StorePublicKeyParams {
    email: string;
    armoredKey: string;
    source?: "wkd" | "hkp" | "autocrypt" | "manual" | "key-gossip";
    verified?: boolean;
}

// ─────────────────────────────────────────────────────────────
//  Messaging Protocol
// ─────────────────────────────────────────────────────────────

/**
 * Протокол повідомлень між Content Script / Popup та Background.
 *
 * Усі методи з кількома параметрами використовують об'єкт для type-safety.
 * Типізація через @webext-core/messaging гарантує end-to-end type checking.
 */
export interface MailShroudMessages {
    // ── Vault lifecycle ────────────────────────────────────
    unlockVault: (masterPassword: string) => Promise<UnlockResult>;
    lockVault: () => Promise<void>;
    isVaultUnlocked: () => Promise<boolean>;
    changeMasterPassword: (params: ChangeMasterPasswordParams) => Promise<void>;

    // ── Private keys ──────────────────────────────────────
    storePrivateKey: (
        params: StorePrivateKeyParams,
    ) => Promise<StorePrivateKeyResult>;
    generateKeyPair: (
        params: GenerateKeyPairParams,
    ) => Promise<GenerateKeyPairResult>;
    listPrivateKeys: () => Promise<KeyInfo[]>;
    deletePrivateKey: (email: string) => Promise<void>;
    exportRevocationCertificate: (email: string) => Promise<string | null>;

    // ── Public keys ───────────────────────────────────────
    getPublicKey: (email: string) => Promise<string | null>;
    storePublicKey: (params: StorePublicKeyParams) => Promise<void>;
    listPublicKeys: () => Promise<KeyInfo[]>;
    deletePublicKey: (email: string) => Promise<void>;

    // ── Crypto operations ─────────────────────────────────
    decryptMessage: (armoredText: string) => Promise<DecryptMessageResult>;
    encryptMessage: (
        params: EncryptMessageParams,
    ) => Promise<EncryptMessageResult>;
}
