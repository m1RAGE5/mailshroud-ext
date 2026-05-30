import * as openpgp from "openpgp";

/**
 * In-memory сховище розблокованих приватних ключів та сесійного пароля.
 * Живе тільки поки Service Worker активний.
 * При termination SW — автоматично очищується (природній auto-lock).
 */
const unlockedKeys = new Map<string, openpgp.PrivateKey>();

// Тимчасове зберігання майстер-пароля для шифрування НОВИХ ключів під час активної сесії
let sessionMasterPassword: string | null = null;

// ─────────────────────────────────────────────────────────────
//  Session Password Operations
// ─────────────────────────────────────────────────────────────

export function setSessionPassword(password: string): void {
    sessionMasterPassword = password;
}

export function getSessionPassword(): string | null {
    return sessionMasterPassword;
}

// ─────────────────────────────────────────────────────────────
//  Cache Operations
// ─────────────────────────────────────────────────────────────

export function cacheUnlockedKey(
    email: string,
    privateKey: openpgp.PrivateKey,
): void {
    unlockedKeys.set(email.toLowerCase(), privateKey);
}

export function getCachedUnlockedKey(
    email: string,
): openpgp.PrivateKey | undefined {
    return unlockedKeys.get(email.toLowerCase());
}

export function removeCachedUnlockedKey(email: string): void {
    unlockedKeys.delete(email.toLowerCase());
}

export function getAllCachedKeys(): Map<string, openpgp.PrivateKey> {
    // Повертаємо копію для ізоляції від зовнішніх мутацій
    return new Map(unlockedKeys);
}

// ─────────────────────────────────────────────────────────────
//  Vault State
// ─────────────────────────────────────────────────────────────

/**
 * Перевірка реального стану vault.
 */
export function isVaultActuallyUnlocked(): boolean {
    return unlockedKeys.size > 0 || sessionMasterPassword !== null;
}

/** Очищує всі ключі з пам'яті та стирає майстер-пароль (lock vault). */
export function clearSessionCache(): void {
    unlockedKeys.clear();
    sessionMasterPassword = null;
}
