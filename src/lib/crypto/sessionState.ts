import * as openpgp from "openpgp";

/**
 * In-memory сховище розблокованих приватних ключів.
 * Живе тільки поки Service Worker активний.
 * При termination SW — автоматично очищується (природній auto-lock).
 *
 * Ключі Map — завжди email у нижньому регістрі.
 */
const unlockedKeys = new Map<string, openpgp.PrivateKey>();

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
    return new Map(unlockedKeys);
}

/**
 * Пошук ключа за Key ID (для ефективного decrypt).
 */
export function findKeyByKeyId(
    keyId: openpgp.KeyID,
): openpgp.PrivateKey | undefined {
    const keyIdHex = keyId.toHex();
    for (const key of unlockedKeys.values()) {
        const allKeyIds = [
            key.getKeyID().toHex(),
            ...key.getSubkeys().map((sk) => sk.getKeyID().toHex()),
        ];
        if (allKeyIds.includes(keyIdHex)) return key;
    }
    return undefined;
}

export function hasAnyUnlockedKey(): boolean {
    return unlockedKeys.size > 0;
}

export function clearAllUnlockedKeys(): void {
    unlockedKeys.clear();
}

/**
 * Alias для зворотної сумісності.
 */
export function clearSessionCache(): void {
    clearAllUnlockedKeys();
}

/**
 * Перевірка реального стану vault.
 * Оскільки ключі тільки в RAM, наявність ключів = vault розблокований.
 * Синхронна — Map.size є синхронною властивістю.
 */
export function isVaultActuallyUnlocked(): boolean {
    return hasAnyUnlockedKey();
}
