import * as openpgp from "openpgp";
import { defineExtensionMessaging } from "@webext-core/messaging";
import { db } from "~/lib/db";
import {
    deriveKey,
    decryptPrivateKey,
    encryptPrivateKey,
    generateSalt,
    initOpenPGP,
    cacheUnlockedKey,
    getCachedUnlockedKey,
    getAllCachedKeys,
    findKeyByKeyId,
    clearSessionCache,
    isVaultActuallyUnlocked,
    validatePublicKey,
    assertUnprotectedPrivateKey,
    getEmailFromKey,
} from "~/lib/crypto";
import type {
    MailShroudMessages,
    UnlockResult,
    StorePrivateKeyParams,
    StorePrivateKeyResult,
    EncryptMessageParams,
    EncryptMessageResult,
} from "~/lib/types/messages";
import {
    checkUnlockAttempt,
    recordFailedAttempt,
    resetAttempts,
    resetAllAttempts,
    VaultLockedError,
    LOCKOUT_DELAYS,
    getState,
} from "~/lib/security/rateLimit";
import { startKeepAlive, stopKeepAlive } from "~/lib/security/vaultKeepAlive";
import { VaultError, VaultErrorCode } from "~/lib/types/error";

const messenger = defineExtensionMessaging<MailShroudMessages>();

const openpgpReady = initOpenPGP().catch((err) => {
    console.error("Failed to initialize OpenPGP:", err);
    throw err;
});

export default defineBackground(() => {
    console.log("MailShroud Background Service Worker started", {
        id: browser.runtime.id,
    });
    setupMessageHandlers();
    setupLifecycleHandlers();
});

function setupMessageHandlers() {
    browser.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === "vault-auto-lock") {
            console.log("[MailShroud] Auto-lock triggered (idle timeout)");
            handleLockVault();
        }
    });

    messenger.onMessage("decryptMessage", async (message) => {
        return await handleDecryptMessage(message.data);
    });

    messenger.onMessage("encryptMessage", async (message) => {
        const { text, recipientEmails, senderEmail } = message.data;
        return await handleEncryptMessage(text, recipientEmails, senderEmail);
    });

    messenger.onMessage("unlockVault", async (message) => {
        return await handleUnlockVault(message.data as string);
    });

    messenger.onMessage("lockVault", () => {
        handleLockVault();
    });
    messenger.onMessage("storePrivateKey", async (message) => {
        const {
            email,
            encryptedArmoredKey,
            salt,
            iv,
            masterPassword,
            forceOverwrite,
        } = message.data;

        if (!forceOverwrite) {
            const existing = await db.privateKeys.get(email.toLowerCase());
            if (existing) {
                throw new Error(
                    `Private key for ${email} already exists. Use forceOverwrite=true to replace.`,
                );
            }
        }

        return await handleStorePrivateKey(
            email.toLowerCase(),
            encryptedArmoredKey,
            salt,
            iv,
            masterPassword,
        );
    });

    messenger.onMessage("getPublicKey", async (message) => {
        return await handleGetPublicKey(message.data as string);
    });

    messenger.onMessage("storePublicKey", async (message) => {
        const { email, armoredKey } = message.data;
        await handleStorePublicKey(email, armoredKey);
    });

    messenger.onMessage("isVaultUnlocked", async () => {
        return isVaultActuallyUnlocked();
    });
}

function setupLifecycleHandlers() {
    browser.runtime.onStartup.addListener(() => {
        console.log("[MailShroud] Browser startup — vault locked by default");
        clearSessionCache();
        stopKeepAlive();
    });

    browser.runtime.onInstalled.addListener((details) => {
        if (details.reason === "install" || details.reason === "update") {
            clearSessionCache();
            stopKeepAlive();
        }
    });
}

function findKeyByKeyIdInSnapshot(
    keyId: openpgp.KeyID,
    snapshot: Map<string, openpgp.PrivateKey>,
): openpgp.PrivateKey | undefined {
    const keyIdHex = keyId.toHex();
    for (const key of snapshot.values()) {
        const allKeyIds = [
            key.getKeyID().toHex(),
            ...key.getSubkeys().map((sk) => sk.getKeyID().toHex()),
        ];
        if (allKeyIds.includes(keyIdHex)) return key;
    }
    return undefined;
}

/**
 * Розшифрування PGP повідомлення.
 */
async function handleDecryptMessage(armoredText: string): Promise<{
    data: string;
    signaturesValid: boolean[];
    signerEmails: (string | null)[];
}> {
    try {
        if (!isVaultActuallyUnlocked()) {
            throw new VaultError(VaultErrorCode.LOCKED, "Vault is locked.");
        }

        const keySnapshot = getAllCachedKeys();
        if (keySnapshot.size === 0) {
            throw new VaultError(
                VaultErrorCode.LOCKED,
                "Vault was locked during operation.",
            );
        }

        if (armoredText.length > 1_000_000) {
            throw new Error("Message too large (max 1MB)");
        }

        await openpgpReady;
        const message = await openpgp.readMessage({
            armoredMessage: armoredText,
        });

        const encryptionKeyIds = await message.getEncryptionKeyIDs();
        if (encryptionKeyIds.length === 0) {
            throw new Error("Message has no encryption key IDs");
        }

        const decryptionKeys: openpgp.PrivateKey[] = [];
        for (const keyId of encryptionKeyIds) {
            const key = findKeyByKeyIdInSnapshot(keyId, keySnapshot);
            if (key) decryptionKeys.push(key);
        }

        if (decryptionKeys.length === 0) {
            throw new VaultError(
                VaultErrorCode.NO_MATCHING_KEY,
                "You don't have a private key that can decrypt this message",
            );
        }

        const allPublicRecords = await db.publicKeys.toArray();
        const verificationKeys: openpgp.Key[] = await Promise.all(
            allPublicRecords.map((r) =>
                openpgp.readKey({ armoredKey: r.armoredKey }),
            ),
        );

        const { data, signatures } = await openpgp.decrypt({
            message,
            decryptionKeys,
            verificationKeys,
            expectSigned: false,
        });

        const signaturesValid: boolean[] = [];
        const signerEmails: (string | null)[] = [];

        if (signatures.length === 0) {
            signaturesValid.push(false);
            signerEmails.push(null);
        } else {
            for (const sig of signatures) {
                try {
                    await sig.verified;
                    signaturesValid.push(true);
                    const keyIdHex = sig.keyID.toHex();
                    const signerKey = verificationKeys.find((k) => {
                        const allKeyIds = [
                            k.getKeyID().toHex(),
                            ...k.subkeys.map((sk) => sk.getKeyID().toHex()),
                        ];
                        return allKeyIds.includes(keyIdHex);
                    });
                    signerEmails.push(
                        signerKey?.users[0]?.userID?.email ?? null,
                    );
                } catch {
                    signaturesValid.push(false);
                    signerEmails.push(null);
                }
            }
        }

        refreshAutoLock();
        return { data: data as string, signaturesValid, signerEmails };
    } catch (error) {
        if (error instanceof VaultError) throw error;
        if (error instanceof VaultLockedError) {
            throw new VaultError(
                VaultErrorCode.RATE_LIMITED,
                error.message,
                error.retryAfterMs,
            );
        }
        throw new VaultError(
            VaultErrorCode.CORRUPTED_DATA,
            `Decryption failed: ${(error as Error).message}`,
        );
    }
}

/**
 * Шифрування повідомлення для отримувачів
 */
async function handleEncryptMessage(
    text: string,
    recipientEmails: string[],
    senderEmail?: string,
): Promise<EncryptMessageResult> {
    try {
        await openpgpReady;
        if (recipientEmails.length === 0) {
            throw new Error("No recipients specified");
        }

        const encryptionKeys: openpgp.Key[] = [];
        for (const email of recipientEmails) {
            const record = await db.publicKeys.get(email.toLowerCase());
            if (!record) {
                throw new Error(`Public key not found for ${email}`);
            }
            const publicKey = await openpgp.readKey({
                armoredKey: record.armoredKey,
            });

            try {
                await publicKey.verifyPrimaryKey();
            } catch (err) {
                throw new Error(
                    `Key for ${email} is invalid: ${(err as Error).message}`,
                );
            }

            if (await publicKey.isRevoked()) {
                throw new Error(`Key for ${email} is revoked`);
            }

            const encryptionKey = await publicKey.getEncryptionKey();
            if (!encryptionKey) {
                throw new Error(
                    `No valid (non-expired) encryption subkey for ${email}`,
                );
            }
            encryptionKeys.push(publicKey);
        }

        const signingKeys: openpgp.PrivateKey[] = [];
        const allOwnKeys = getAllCachedKeys();
        let signingKey: openpgp.PrivateKey | undefined;

        if (senderEmail) {
            signingKey = getCachedUnlockedKey(senderEmail);
        }

        if (!signingKey) {
            if (allOwnKeys.size === 1) {
                signingKey = allOwnKeys.values().next().value ?? undefined;
            } else if (allOwnKeys.size > 1) {
                throw new Error(
                    "Multiple private keys available. Please select a signing key explicitly.",
                );
            } else if (allOwnKeys.size === 0) {
                if (import.meta.env.DEV) {
                    console.warn(
                        "No unlocked private keys — message will NOT be signed",
                    );
                }
            }
        }

        if (signingKey) {
            signingKeys.push(signingKey);
        } else {
            console.warn(
                "[MailShroud] No unlocked private key available — message will NOT be signed",
            );
        }

        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text }),
            encryptionKeys,
            signingKeys,
        });

        if (signingKeys.length > 0) {
            refreshAutoLock();
        }

        return {
            encrypted: encrypted as string,
            signed: signingKeys.length > 0,
            signerEmail: signingKey ? getEmailFromKey(signingKey) : undefined,
        };
    } catch (error) {
        if (import.meta.env.DEV) console.error("Encryption failed:", error);
        else console.error("Encryption failed:", (error as Error).message);
        throw error;
    }
}

/**
 * Розблокування vault з Master Password.
 * Ключі зберігаються як openpgp.PrivateKey об'єкти в RAM.
 */
async function handleUnlockVault(
    masterPassword: string,
): Promise<UnlockResult> {
    await openpgpReady;
    const allPrivateKeys = await db.privateKeys.toArray();

    if (allPrivateKeys.length === 0) {
        return { success: false, unlocked: 0, failed: 0, failedEmails: [] };
    }

    const lockedEmails: string[] = [];
    for (const keyRecord of allPrivateKeys) {
        try {
            await checkUnlockAttempt(keyRecord.email);
        } catch (err) {
            if (err instanceof VaultLockedError) {
                lockedEmails.push(keyRecord.email);
            } else {
                throw err;
            }
        }
    }

    if (lockedEmails.length === allPrivateKeys.length) {
        const state = await getState();
        const maxLockedUntil = Math.max(
            ...lockedEmails.map((e) => state[e]?.lockedUntil ?? 0),
        );
        const retryAfterMs = Math.max(0, maxLockedUntil - Date.now());
        throw new VaultLockedError(retryAfterMs);
    }

    const unlockableKeys = allPrivateKeys.filter(
        (k) => !lockedEmails.includes(k.email),
    );

    const results = await Promise.allSettled(
        unlockableKeys.map((keyRecord) =>
            unlockSingleKey(keyRecord, masterPassword),
        ),
    );

    let unlockedCount = 0;
    const failedEmails: string[] = [];

    for (let i = 0; i < results.length; i++) {
        const result = results[i]!;
        const keyRecord = unlockableKeys[i]!;

        if (result.status === "fulfilled") {
            if (result.value.success) {
                unlockedCount++;
                await resetAttempts(keyRecord.email);
            } else {
                failedEmails.push(keyRecord.email);
                await recordFailedAttempt(keyRecord.email);
                if (import.meta.env.DEV) {
                    console.warn(
                        `[MailShroud] Email mismatch for key ${keyRecord.email} — ` +
                            `possible vault tampering`,
                    );
                }
            }
        } else {
            if (result.reason instanceof VaultLockedError) {
                throw result.reason;
            }

            await recordFailedAttempt(keyRecord.email);
            failedEmails.push(keyRecord.email);
            if (import.meta.env.DEV) {
                console.warn(
                    `Failed to unlock key for ${keyRecord.email}:`,
                    result.reason,
                );
            }
        }
    }

    if (unlockedCount > 0) {
        scheduleAutoLock();
        startKeepAlive();
    }

    return {
        success: unlockedCount > 0,
        unlocked: unlockedCount,
        failed: failedEmails.length,
        failedEmails,
    };
}

/** Внутрішня helper-функція для одного ключа */
async function unlockSingleKey(
    keyRecord: {
        email: string;
        encryptedArmoredKey: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<{ success: boolean }> {
    const cryptoKey = await deriveKey(masterPassword, keyRecord.salt);
    let armoredKey = "";
    try {
        armoredKey = await decryptPrivateKey(
            keyRecord.encryptedArmoredKey,
            keyRecord.iv,
            cryptoKey,
            keyRecord.email,
        );
    } catch (err) {
        armoredKey = "";
        throw err;
    }

    try {
        const privateKey = await openpgp.readPrivateKey({ armoredKey });
        assertUnprotectedPrivateKey(privateKey);

        const matchesEmail = privateKey.users.some((user) => {
            const userEmail = user.userID?.email;
            return userEmail?.toLowerCase() === keyRecord.email.toLowerCase();
        });

        if (!matchesEmail) {
            return { success: false };
        }

        cacheUnlockedKey(keyRecord.email, privateKey);
        return { success: true };
    } finally {
        armoredKey = "";
    }
}

const AUTO_LOCK_MINUTES = 15;

function scheduleAutoLock(): void {
    browser.alarms.create("vault-auto-lock", {
        delayInMinutes: AUTO_LOCK_MINUTES,
    });
}

function cancelAutoLock(): void {
    browser.alarms.clear("vault-auto-lock");
}

/** Оновити таймер авто-локу (викликати при активності) */
function refreshAutoLock(): void {
    if (!isVaultActuallyUnlocked()) return;
    cancelAutoLock();
    scheduleAutoLock();
}

/**
 * Блокування vault
 */
function handleLockVault(): void {
    cancelAutoLock();
    clearSessionCache();
    stopKeepAlive();
    console.log("Vault locked");
}

/**
 * Збереження зашифрованого приватного ключа
 */
async function handleStorePrivateKey(
    email: string,
    encryptedArmoredKey: string,
    salt: string,
    iv: string,
    masterPassword: string,
): Promise<StorePrivateKeyResult> {
    if (!email || !email.includes("@")) {
        throw new Error("Invalid email format");
    }
    if (
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
            encryptedArmoredKey,
        )
    ) {
        throw new Error("Invalid base64 format");
    }
    if (!/^[0-9a-f]{64}$/i.test(salt)) {
        throw new Error("Invalid salt: expected 64 hex chars (32 bytes)");
    }
    if (!/^[0-9a-f]{24}$/i.test(iv)) {
        throw new Error("Invalid iv: expected 24 hex chars (12 bytes)");
    }

    const cryptoKey = await deriveKey(masterPassword, salt);
    let armoredKey = "";
    let realFingerprint = "";
    try {
        armoredKey = await decryptPrivateKey(
            encryptedArmoredKey,
            iv,
            cryptoKey,
            email.toLowerCase(),
        );
        const privateKey = await openpgp.readPrivateKey({ armoredKey });
        assertUnprotectedPrivateKey(privateKey);

        const matchesEmail = privateKey.users.some((user) => {
            const userEmail = user.userID?.email;
            return userEmail?.toLowerCase() === email.toLowerCase();
        });
        if (!matchesEmail) {
            throw new Error(`Key does not contain email: ${email}`);
        }

        realFingerprint = privateKey.getFingerprint();
    } finally {
        armoredKey = "";
    }

    await db.privateKeys.put({
        email: email.toLowerCase(),
        encryptedArmoredKey,
        salt,
        iv,
        keyFingerprint: realFingerprint,
        createdAt: Date.now(),
        updatedAt: Date.now(),
    });

    return {
        fingerprint: realFingerprint,
        email: email.toLowerCase(),
    };
}

/**
 * Отримання публічного ключа
 */
async function handleGetPublicKey(email: string): Promise<string | null> {
    const record = await db.publicKeys.get(email);
    return record ? record.armoredKey : null;
}

/**
 * Збереження публічного ключа
 */
async function handleStorePublicKey(
    email: string,
    armoredKey: string,
): Promise<void> {
    const validatedKey = await validatePublicKey(armoredKey, email);

    await db.publicKeys.put({
        email: email.toLowerCase(),
        armoredKey,
        keyFingerprint: validatedKey.getFingerprint(),
        source: "manual",
        verified: false,
        createdAt: Date.now(),
    });

    console.log(`Public key stored for ${email}`);
}
