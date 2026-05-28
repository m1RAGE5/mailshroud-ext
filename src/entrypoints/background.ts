import * as openpgp from "openpgp";
import { defineExtensionMessaging } from "@webext-core/messaging";
import { db } from "~/lib/db";
import {
    deriveKey,
    decryptPrivateKey,
    encryptPrivateKey,
    generateSalt,
    generateKeyPair,
    initOpenPGP,
    cacheUnlockedKey,
    getCachedUnlockedKey,
    getAllCachedKeys,
    removeCachedUnlockedKey,
    clearSessionCache,
    isVaultActuallyUnlocked,
    validatePublicKey,
    assertUnprotectedPrivateKey,
    getEmailFromKey,
} from "~/lib/crypto";
import type {
    MailShroudMessages,
    UnlockResult,
    StorePrivateKeyResult,
    GenerateKeyPairResult,
    EncryptMessageResult,
    DecryptMessageResult,
    KeyInfo,
} from "~/lib/types/messages";
import {
    checkUnlockAttempt,
    recordFailedAttempt,
    resetAttempts,
    VaultLockedError,
    getState,
} from "~/lib/security/rateLimit";
import { startKeepAlive, stopKeepAlive } from "~/lib/security/vaultKeepAlive";
import { VaultError, VaultErrorCode } from "~/lib/types/error";

const messenger = defineExtensionMessaging<MailShroudMessages>();
const openpgpReady = initOpenPGP().catch((err) => {
    console.error("Failed to initialize OpenPGP:", err);
    throw err;
});

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

const AUTO_LOCK_MINUTES = 15;
const MAX_MESSAGE_SIZE = 1_000_000; // 1MB

const RE_BASE64 =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RE_SALT = /^[0-9a-f]{64}$/i;
const RE_IV = /^[0-9a-f]{24}$/i;

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

/** Усі KeyID (primary + subkeys) для одного ключа */
function collectKeyIds(key: openpgp.Key): string[] {
    return [
        key.getKeyID().toHex(),
        ...key.subkeys.map((sk) => sk.getKeyID().toHex()),
    ];
}

/** Знайти приватний ключ у snapshot за KeyID повідомлення */
function findPrivateKeyById(
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
function findPublicKeyById(
    keyId: string,
    keys: openpgp.Key[],
): openpgp.Key | undefined {
    return keys.find((k) => collectKeyIds(k).includes(keyId));
}

/**
 * Спільна логіка: розшифрувати vault-запис → прочитати PrivateKey
 * → перевірити, що він без passphrase → звірити email.
 */
async function decryptAndVerifyVaultKey(
    record: {
        email: string;
        encryptedArmoredKey: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<openpgp.PrivateKey> {
    const cryptoKey = await deriveKey(masterPassword, record.salt);
    let armoredKey = await decryptPrivateKey(
        record.encryptedArmoredKey,
        record.iv,
        cryptoKey,
        record.email,
    );

    const privateKey = await openpgp.readPrivateKey({ armoredKey });
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
async function decryptVaultToArmored(
    record: {
        email: string;
        encryptedArmoredKey: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<string> {
    const cryptoKey = await deriveKey(masterPassword, record.salt);
    return decryptPrivateKey(
        record.encryptedArmoredKey,
        record.iv,
        cryptoKey,
        record.email,
    );
}

/** Обгорнути довільну помилку у VaultError */
function toVaultError(
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

/** Тип signatures з openpgp.decrypt() */
type DecryptSignatures = Awaited<
    ReturnType<typeof openpgp.decrypt>
>["signatures"];

// ─────────────────────────────────────────────────────────────
//  Entrypoint
// ─────────────────────────────────────────────────────────────

export default defineBackground(() => {
    console.log("MailShroud Background started", { id: browser.runtime.id });
    setupMessageHandlers();
    setupLifecycleHandlers();
});

// ─────────────────────────────────────────────────────────────
//  Lifecycle
// ─────────────────────────────────────────────────────────────

function setupLifecycleHandlers(): void {
    browser.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === "vault-auto-lock") {
            console.log("[MailShroud] Auto-lock triggered");
            handleLockVault();
        }
    });

    const lockAll = () => {
        clearSessionCache();
        stopKeepAlive();
    };

    browser.runtime.onStartup.addListener(() => {
        console.log("[MailShroud] Browser startup — vault locked");
        lockAll();
    });

    browser.runtime.onInstalled.addListener((details) => {
        if (details.reason === "install" || details.reason === "update")
            lockAll();
    });
}

// ─────────────────────────────────────────────────────────────
//  Message handlers
// ─────────────────────────────────────────────────────────────

function setupMessageHandlers(): void {
    // ── Crypto operations ──────────────────────────────────
    messenger.onMessage("decryptMessage", (m) => handleDecryptMessage(m.data));
    messenger.onMessage("encryptMessage", (m) =>
        handleEncryptMessage(
            m.data.text,
            m.data.recipientEmails,
            m.data.senderEmail,
        ),
    );

    // ── Vault lifecycle ────────────────────────────────────
    messenger.onMessage("unlockVault", (m) => handleUnlockVault(m.data));
    messenger.onMessage("lockVault", () => {
        handleLockVault();
    });
    messenger.onMessage("isVaultUnlocked", async () =>
        isVaultActuallyUnlocked(),
    );
    messenger.onMessage("changeMasterPassword", (m) =>
        handleChangeMasterPassword(m.data.currentPassword, m.data.newPassword),
    );

    // ── Private keys ───────────────────────────────────────
    messenger.onMessage("storePrivateKey", async (m) => {
        const {
            email,
            encryptedArmoredKey,
            salt,
            iv,
            masterPassword,
            forceOverwrite,
        } = m.data;
        const emailLower = email.toLowerCase();
        if (!forceOverwrite) {
            const existing = await db.privateKeys.get(emailLower);
            if (existing) {
                throw new VaultError(
                    VaultErrorCode.KEY_ALREADY_EXISTS,
                    `Private key for ${emailLower} already exists. Use forceOverwrite=true.`,
                );
            }
        }
        return handleStorePrivateKey(
            emailLower,
            encryptedArmoredKey,
            salt,
            iv,
            masterPassword,
        );
    });
    messenger.onMessage("generateKeyPair", (m) =>
        handleGenerateKeyPair(m.data),
    );
    messenger.onMessage("listPrivateKeys", () => handleListPrivateKeys());
    messenger.onMessage("deletePrivateKey", (m) =>
        handleDeletePrivateKey(m.data),
    );
    messenger.onMessage("exportRevocationCertificate", (m) =>
        handleExportRevocationCertificate(m.data),
    );

    // ── Public keys ────────────────────────────────────────
    messenger.onMessage("getPublicKey", (m) => handleGetPublicKey(m.data));
    messenger.onMessage("storePublicKey", (m) =>
        handleStorePublicKey(
            m.data.email,
            m.data.armoredKey,
            m.data.source,
            m.data.verified,
        ),
    );
    messenger.onMessage("listPublicKeys", () => handleListPublicKeys());
    messenger.onMessage("deletePublicKey", (m) =>
        handleDeletePublicKey(m.data),
    );
}

// ─────────────────────────────────────────────────────────────
//  Decrypt
// ─────────────────────────────────────────────────────────────

async function handleDecryptMessage(
    armoredText: string,
): Promise<DecryptMessageResult> {
    try {
        if (!isVaultActuallyUnlocked()) {
            throw new VaultError(VaultErrorCode.LOCKED, "Vault is locked.");
        }
        if (armoredText.length > MAX_MESSAGE_SIZE) {
            throw new Error("Message too large (max 1MB)");
        }

        await openpgpReady;
        const message = await openpgp.readMessage({
            armoredMessage: armoredText,
        });

        const snapshot = getAllCachedKeys();
        const encryptionKeyIds = await message.getEncryptionKeyIDs();
        if (encryptionKeyIds.length === 0) {
            throw new Error("Message has no encryption key IDs");
        }

        const decryptionKeys = encryptionKeyIds
            .map((id) => findPrivateKeyById(id, snapshot))
            .filter((k): k is openpgp.PrivateKey => !!k);

        if (decryptionKeys.length === 0) {
            throw new VaultError(
                VaultErrorCode.NO_MATCHING_KEY,
                "You don't have a private key that can decrypt this message",
            );
        }

        const verificationKeys = await loadAllPublicKeys();
        const { data, signatures } = await openpgp.decrypt({
            message,
            decryptionKeys,
            verificationKeys,
            expectSigned: false,
        });

        const result = await verifySignatures(signatures, verificationKeys);
        refreshAutoLock();
        return { data: data as string, ...result };
    } catch (err) {
        throw toVaultError(
            err,
            VaultErrorCode.CORRUPTED_DATA,
            "Decryption failed",
        );
    }
}

async function loadAllPublicKeys(): Promise<openpgp.Key[]> {
    const records = await db.publicKeys.toArray();
    return Promise.all(
        records.map((r) => openpgp.readKey({ armoredKey: r.armoredKey })),
    );
}

async function verifySignatures(
    signatures: DecryptSignatures,
    verificationKeys: openpgp.Key[],
): Promise<{ signaturesValid: boolean[]; signerEmails: (string | null)[] }> {
    const signaturesValid: boolean[] = [];
    const signerEmails: (string | null)[] = [];

    if (!signatures || signatures.length === 0) {
        return { signaturesValid: [false], signerEmails: [null] };
    }

    for (const sig of signatures) {
        try {
            await sig.verified;
            signaturesValid.push(true);
            const signer = findPublicKeyById(
                sig.keyID.toHex(),
                verificationKeys,
            );
            signerEmails.push(signer?.users[0]?.userID?.email ?? null);
        } catch {
            signaturesValid.push(false);
            signerEmails.push(null);
        }
    }
    return { signaturesValid, signerEmails };
}

// ─────────────────────────────────────────────────────────────
//  Encrypt
// ─────────────────────────────────────────────────────────────

async function handleEncryptMessage(
    text: string,
    recipientEmails: string[],
    senderEmail?: string,
): Promise<EncryptMessageResult> {
    try {
        if (text.length > MAX_MESSAGE_SIZE)
            throw new Error("Message too large (max 1MB)");

        await openpgpReady;

        if (recipientEmails.length === 0)
            throw new Error("No recipients specified");

        const encryptionKeys = await Promise.all(
            recipientEmails.map(loadAndValidateRecipientKey),
        );

        const signingKey = pickSigningKey(senderEmail);
        const signingKeys = signingKey ? [signingKey] : [];

        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text }),
            encryptionKeys,
            signingKeys,
        });

        if (signingKey) refreshAutoLock();

        return {
            encrypted: encrypted as string,
            signed: signingKeys.length > 0,
            signerEmail: signingKey ? getEmailFromKey(signingKey) : undefined,
        };
    } catch (err) {
        if (import.meta.env.DEV) console.error("Encryption failed:", err);
        throw err;
    }
}

async function loadAndValidateRecipientKey(
    email: string,
): Promise<openpgp.Key> {
    const record = await db.publicKeys.get(email.toLowerCase());
    if (!record) throw new Error(`Public key not found for ${email}`);

    const publicKey = await openpgp.readKey({ armoredKey: record.armoredKey });
    try {
        await publicKey.verifyPrimaryKey();
    } catch (err) {
        throw new Error(
            `Key for ${email} is invalid: ${(err as Error).message}`,
        );
    }
    if (await publicKey.isRevoked()) {
        throw new VaultError(
            VaultErrorCode.KEY_REVOKED,
            `Key for ${email} is revoked`,
        );
    }
    const expiration = await publicKey.getExpirationTime();
    if (
        expiration !== Infinity &&
        expiration !== null &&
        expiration < new Date()
    ) {
        throw new VaultError(
            VaultErrorCode.KEY_EXPIRED,
            `Key for ${email} is expired`,
        );
    }

    const encKey = await publicKey.getEncryptionKey();
    if (!encKey) throw new Error(`No valid encryption subkey for ${email}`);
    return publicKey;
}

function pickSigningKey(senderEmail?: string): openpgp.PrivateKey | undefined {
    const allOwnKeys = getAllCachedKeys();

    if (senderEmail) {
        const key = getCachedUnlockedKey(senderEmail);
        if (key) return key;
    }
    if (allOwnKeys.size === 1)
        return allOwnKeys.values().next().value ?? undefined;
    if (allOwnKeys.size > 1) {
        throw new Error(
            "Multiple private keys available. Please select a signing key explicitly.",
        );
    }
    if (import.meta.env.DEV) {
        console.warn("No unlocked private keys — message will NOT be signed");
    }
    return undefined;
}

// ─────────────────────────────────────────────────────────────
//  Unlock / Lock
// ─────────────────────────────────────────────────────────────

async function handleUnlockVault(
    masterPassword: string,
): Promise<UnlockResult> {
    await openpgpReady;
    const allPrivateKeys = await db.privateKeys.toArray();
    if (allPrivateKeys.length === 0) {
        return { success: false, unlocked: 0, failed: 0, failedEmails: [] };
    }

    const lockedEmails: string[] = [];
    for (const rec of allPrivateKeys) {
        try {
            await checkUnlockAttempt(rec.email);
        } catch (err) {
            if (err instanceof VaultLockedError) lockedEmails.push(rec.email);
            else throw err;
        }
    }

    if (lockedEmails.length === allPrivateKeys.length) {
        const state = await getState();
        const maxUntil = Math.max(
            ...lockedEmails.map((e) => state[e]?.lockedUntil ?? 0),
        );
        throw new VaultLockedError(Math.max(0, maxUntil - Date.now()));
    }

    const unlockable = allPrivateKeys.filter(
        (k) => !lockedEmails.includes(k.email),
    );
    const results = await Promise.allSettled(
        unlockable.map((rec) => unlockSingleKey(rec, masterPassword)),
    );

    let unlockedCount = 0;
    const failedEmails: string[] = [];
    for (let i = 0; i < results.length; i++) {
        const r = results[i]!;
        const rec = unlockable[i]!;

        if (r.status === "fulfilled" && r.value) {
            unlockedCount++;
            await resetAttempts(rec.email);
        } else {
            failedEmails.push(rec.email);
            await recordFailedAttempt(rec.email);
            if (r.status === "rejected" && r.reason instanceof VaultLockedError)
                throw r.reason;
            if (import.meta.env.DEV) {
                console.warn(
                    `Failed to unlock ${rec.email}:`,
                    r.status === "rejected" ? r.reason : "email mismatch",
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

async function unlockSingleKey(
    record: {
        email: string;
        encryptedArmoredKey: string;
        salt: string;
        iv: string;
    },
    masterPassword: string,
): Promise<boolean> {
    try {
        const privateKey = await decryptAndVerifyVaultKey(
            record,
            masterPassword,
        );
        cacheUnlockedKey(record.email, privateKey);
        return true;
    } catch {
        return false;
    }
}

// ─────────────────────────────────────────────────────────────
//  Auto-lock
// ─────────────────────────────────────────────────────────────

function scheduleAutoLock(): void {
    browser.alarms.create("vault-auto-lock", {
        delayInMinutes: AUTO_LOCK_MINUTES,
    });
}
function cancelAutoLock(): void {
    browser.alarms.clear("vault-auto-lock");
}
function refreshAutoLock(): void {
    if (!isVaultActuallyUnlocked()) return;
    cancelAutoLock();
    scheduleAutoLock();
}
function handleLockVault(): void {
    cancelAutoLock();
    clearSessionCache();
    stopKeepAlive();
    console.log("[MailShroud] Vault locked");
}

// ─────────────────────────────────────────────────────────────
//  Store / Get / List / Delete keys
// ─────────────────────────────────────────────────────────────

async function handleStorePrivateKey(
    email: string,
    encryptedArmoredKey: string,
    salt: string,
    iv: string,
    masterPassword: string,
): Promise<StorePrivateKeyResult> {
    if (!email.includes("@")) throw new Error("Invalid email format");
    if (!RE_BASE64.test(encryptedArmoredKey))
        throw new Error("Invalid base64 format");
    if (!RE_SALT.test(salt))
        throw new Error("Invalid salt: expected 64 hex chars");
    if (!RE_IV.test(iv)) throw new Error("Invalid iv: expected 24 hex chars");

    const privateKey = await decryptAndVerifyVaultKey(
        { email, encryptedArmoredKey, salt, iv },
        masterPassword,
    );
    const fingerprint = privateKey.getFingerprint();

    await db.privateKeys.put({
        email,
        encryptedArmoredKey,
        salt,
        iv,
        keyFingerprint: fingerprint,
        createdAt: Date.now(),
        updatedAt: Date.now(),
    });

    return { fingerprint, email };
}

async function handleGetPublicKey(email: string): Promise<string | null> {
    const record = await db.publicKeys.get(email.toLowerCase());
    return record?.armoredKey ?? null;
}

async function handleStorePublicKey(
    email: string,
    armoredKey: string,
    source: "wkd" | "hkp" | "autocrypt" | "manual" | "key-gossip" = "manual",
    verified = false,
): Promise<void> {
    const validatedKey = await validatePublicKey(armoredKey, email);
    await db.publicKeys.put({
        email: email.toLowerCase(),
        armoredKey,
        keyFingerprint: validatedKey.getFingerprint(),
        source,
        verified,
        createdAt: Date.now(),
    });
    console.log(
        `[MailShroud] Public key stored for ${email} (source=${source})`,
    );
}

async function handleListPrivateKeys(): Promise<KeyInfo[]> {
    const records = await db.privateKeys.toArray();
    return records.map((r) => ({
        email: r.email,
        fingerprint: r.keyFingerprint,
        createdAt: r.createdAt,
    }));
}

async function handleListPublicKeys(): Promise<KeyInfo[]> {
    const records = await db.publicKeys.toArray();
    return records.map((r) => ({
        email: r.email,
        fingerprint: r.keyFingerprint,
        createdAt: r.createdAt,
        source: r.source,
        verified: r.verified,
    }));
}

async function handleDeletePrivateKey(email: string): Promise<void> {
    const emailLower = email.toLowerCase();
    await db.transaction("rw", db.privateKeys, db.settings, async () => {
        await db.privateKeys.delete(emailLower);
        await db.settings.delete(`revocation:${emailLower}`);
    });
    removeCachedUnlockedKey(emailLower);
    console.log(`[MailShroud] Private key deleted for ${emailLower}`);
}

async function handleDeletePublicKey(email: string): Promise<void> {
    await db.publicKeys.delete(email.toLowerCase());
    console.log(`[MailShroud] Public key deleted for ${email}`);
}

// ─────────────────────────────────────────────────────────────
//  Generate key pair
// ─────────────────────────────────────────────────────────────

async function handleGenerateKeyPair(params: {
    email: string;
    name?: string;
    masterPassword: string;
}): Promise<GenerateKeyPairResult> {
    await openpgpReady;
    const emailLower = params.email.toLowerCase();

    const existing = await db.privateKeys.get(emailLower);
    if (existing) {
        throw new VaultError(
            VaultErrorCode.KEY_ALREADY_EXISTS,
            `Private key for ${emailLower} already exists`,
        );
    }

    // Генерація v6 ключа (curve25519 + AEAD)
    const { privateKey, publicKey, revocationCertificate } =
        await generateKeyPair(emailLower, params.name);

    // Шифрування приватного ключа майстер-паролем
    const salt = generateSalt();
    const cryptoKey = await deriveKey(params.masterPassword, salt);
    const { encryptedData, iv } = await encryptPrivateKey(
        privateKey,
        cryptoKey,
        emailLower,
    );

    // Читання для fingerprint-ів
    const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const pubKeyObj = await openpgp.readKey({ armoredKey: publicKey });

    // Атомарне збереження в БД
    await db.transaction(
        "rw",
        db.privateKeys,
        db.publicKeys,
        db.settings,
        async () => {
            await db.privateKeys.add({
                email: emailLower,
                encryptedArmoredKey: encryptedData,
                salt,
                iv,
                keyFingerprint: privKeyObj.getFingerprint(),
                createdAt: Date.now(),
                updatedAt: Date.now(),
            });

            await db.publicKeys.add({
                email: emailLower,
                armoredKey: publicKey,
                keyFingerprint: pubKeyObj.getFingerprint(),
                source: "manual",
                verified: true, // self-generated = trusted
                createdAt: Date.now(),
            });

            // Revocation certificate зберігається окремо в settings
            await db.settings.put({
                key: `revocation:${emailLower}`,
                value: revocationCertificate,
            });
        },
    );

    return {
        privateKeyFingerprint: privKeyObj.getFingerprint(),
        publicKeyArmored: publicKey,
        revocationCertificate,
        email: emailLower,
    };
}

// ─────────────────────────────────────────────────────────────
//  Change master password
// ─────────────────────────────────────────────────────────────

async function handleChangeMasterPassword(
    currentPassword: string,
    newPassword: string,
): Promise<void> {
    await openpgpReady;
    const allKeys = await db.privateKeys.toArray();
    if (allKeys.length === 0) return;

    const decryptedArmored: Array<{
        record: (typeof allKeys)[number];
        armoredKey: string;
    }> = [];

    for (const record of allKeys) {
        try {
            const armoredKey = await decryptVaultToArmored(
                record,
                currentPassword,
            );
            decryptedArmored.push({ record, armoredKey });
        } catch {
            decryptedArmored.length = 0;
            throw new VaultError(
                VaultErrorCode.INVALID_PASSWORD,
                "Current master password is incorrect",
            );
        }
    }

    const updates: Array<{
        email: string;
        encryptedArmoredKey: string;
        salt: string;
        iv: string;
    }> = [];

    for (const { record, armoredKey } of decryptedArmored) {
        const newSalt = generateSalt();
        const newCryptoKey = await deriveKey(newPassword, newSalt);

        // ✅ Беремо IV з результату шифрування
        const { encryptedData, iv: newIv } = await encryptPrivateKey(
            armoredKey,
            newCryptoKey,
            record.email,
        );

        updates.push({
            email: record.email,
            encryptedArmoredKey: encryptedData,
            salt: newSalt,
            iv: newIv,
        });
    }

    decryptedArmored.length = 0;

    await db.transaction("rw", db.privateKeys, async () => {
        for (const u of updates) {
            await db.privateKeys.update(u.email, {
                encryptedArmoredKey: u.encryptedArmoredKey,
                salt: u.salt,
                iv: u.iv,
                updatedAt: Date.now(),
            });
        }
    });

    handleLockVault();
    console.log("[MailShroud] Master password changed successfully");
}

// ─────────────────────────────────────────────────────────────
//  Export revocation certificate
// ─────────────────────────────────────────────────────────────

async function handleExportRevocationCertificate(
    email: string,
): Promise<string | null> {
    const emailLower = email.toLowerCase();
    const record = await db.settings.get(`revocation:${emailLower}`);
    if (!record || typeof record.value !== "string") return null;
    return record.value;
}
