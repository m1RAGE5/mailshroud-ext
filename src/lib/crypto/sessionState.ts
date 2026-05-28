import * as openpgp from "openpgp";

/**
 * In-memory сховище розблокованих приватних ключів.
 * Живе тільки поки Service Worker активний.
 * При termination SW — автоматично очищується (природній auto-lock).
 *
 * Ключі Map — завжди email у нижньому регістрі.
 */
const unlockedKeys = new Map<string, openpgp.PrivateKey>();

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
 * Синхронна — Map.size є синхронною властивістю.
 */
export function isVaultActuallyUnlocked(): boolean {
    return unlockedKeys.size > 0;
}

/** Очищує всі ключі з пам'яті (lock vault). */
export function clearSessionCache(): void {
    unlockedKeys.clear();
}
