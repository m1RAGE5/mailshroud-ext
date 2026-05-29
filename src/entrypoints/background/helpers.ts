import * as openpgp from "openpgp";
import {
    deriveKey,
    decryptPrivateKey,
    assertUnprotectedPrivateKey,
    initOpenPGP,
} from "~/lib/crypto";
import { VaultError, VaultErrorCode } from "~/lib/types/error";
import { VaultLockedError } from "~/lib/security/rateLimit";

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

export const MAX_MESSAGE_SIZE = 1_000_000; // 1MB
export const RE_BASE64 =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const RE_SALT = /^[0-9a-f]{64}$/i;
export const RE_IV = /^[0-9a-f]{24}$/i;

export const openpgpReady = initOpenPGP().catch((err) => {
    console.error("Failed to initialize OpenPGP:", err);
    throw err;
});

// ─────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────

/** Тип signatures з openpgp.decrypt() */
export type DecryptSignatures = Awaited<
    ReturnType<typeof openpgp.decrypt>
>["signatures"];

// ─────────────────────────────────────────────────────────────
//  Key ID utilities
// ─────────────────────────────────────────────────────────────

/** Усі KeyID (primary + subkeys) для одного ключа */
export function collectKeyIds(key: openpgp.Key): string[] {
    return [
        key.getKeyID().toHex(),
        ...key.subkeys.map((sk) => sk.getKeyID().toHex()),
    ];
}

/** Знайти приватний ключ у snapshot за KeyID повідомлення */
export function findPrivateKeyById(
    keyId: openpgp.KeyID,
    snapshot: Map<string, openpgp.PrivateKey>,
): openpgp.PrivateKey | undefined {
    const hex = keyId.toHex();
    for (const key of snapshot.values()) {
        if (collectKeyIds(key).includes(hex)) return key;
    }
    return undefined;
}

/** Знайти публічний ключ у масиві за KeyID */
export function findPublicKeyById(
    keyId: string,
    keys: openpgp.Key[],
): openpgp.Key | undefined {
    return keys.find((k) => collectKeyIds(k).includes(keyId));
}

// ─────────────────────────────────────────────────────────────
//  Vault decryption helpers
// ─────────────────────────────────────────────────────────────

/**
 * Спільна логіка: розшифрувати vault-запис → прочитати PrivateKey
 * → перевірити, що він без passphrase → звірити email.
 */
export async function decryptAndVerifyVaultKey(
    record: {
        email: string;
        encryptedKeyBase64: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<openpgp.PrivateKey> {
    const cryptoKey = await deriveKey(masterPassword, record.salt);
    const armoredKey = await decryptPrivateKey(
        record.encryptedKeyBase64,
        record.iv,
        cryptoKey,
        record.email,
    );
    const privateKey = await openpgp.readPrivateKey({ armoredKey });

    if (privateKey.keyPacket.version !== 6) {
        throw new Error(
            `Only v6 keys supported. Got v${privateKey.keyPacket.version}`,
        );
    }

    assertUnprotectedPrivateKey(privateKey);

    const matchesEmail = privateKey.users.some(
        (u) => u.userID?.email?.toLowerCase() === record.email.toLowerCase(),
    );

    if (!matchesEmail) {
        throw new Error(`Key does not contain email: ${record.email}`);
    }

    return privateKey;
}

/** Тільки розшифрувати vault-запис до armored-строки (без валідації) */
export async function decryptVaultToArmored(
    record: {
        email: string;
        encryptedKeyBase64: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<string> {
    const cryptoKey = await deriveKey(masterPassword, record.salt);
    return decryptPrivateKey(
        record.encryptedKeyBase64,
        record.iv,
        cryptoKey,
        record.email,
    );
}

// ─────────────────────────────────────────────────────────────
//  Error handling
// ─────────────────────────────────────────────────────────────

/** Обгорнути довільну помилку у VaultError */
export function toVaultError(
    err: unknown,
    fallbackCode: VaultErrorCode,
    msg: string,
): VaultError {
    if (err instanceof VaultError) return err;
    if (err instanceof VaultLockedError) {
        return new VaultError(
            VaultErrorCode.RATE_LIMITED,
            err.message,
            err.retryAfterMs,
        );
    }
    return new VaultError(fallbackCode, `${msg}: ${(err as Error).message}`);
}
