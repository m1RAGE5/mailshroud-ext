import * as openpgp from "openpgp";
import { db } from "~/lib/db";
import {
    deriveKey,
    encryptPrivateKey,
    decryptPrivateKey,
    generateSalt,
    generateKeyPair,
    validatePublicKey,
    removeCachedUnlockedKey,
    getSessionPassword,
    setSessionPassword,
    cacheUnlockedKey,
} from "~/lib/crypto";
import type {
    StorePrivateKeyResult,
    GenerateKeyPairResult,
    KeyInfo,
} from "~/lib/types/messages";
import { VaultError, VaultErrorCode } from "~/lib/types/error";

// Спільні утиліти (будуть у helpers.ts)
import {
    decryptAndVerifyVaultKey,
    openpgpReady,
    RE_BASE64,
    RE_SALT,
    RE_IV,
} from "./helpers";

// Для auto-lock при ініціалізації сесії
import { refreshAutoLock } from "./vault";
import { startKeepAlive } from "~/lib/security/vaultKeepAlive";

// ─────────────────────────────────────────────────────────────
//  Store private key
// ─────────────────────────────────────────────────────────────

export async function handleStorePrivateKey(
    email: string,
    encryptedKeyBase64: string,
    salt: string,
    iv: string,
    masterPassword: string,
): Promise<StorePrivateKeyResult> {
    if (!email.includes("@")) throw new Error("Invalid email format");
    if (!RE_BASE64.test(encryptedKeyBase64))
        throw new Error("Invalid base64 format");
    if (!RE_SALT.test(salt))
        throw new Error("Invalid salt: expected 64 hex chars");
    if (!RE_IV.test(iv)) throw new Error("Invalid iv: expected 24 hex chars");

    const privateKey = await decryptAndVerifyVaultKey(
        { email, encryptedKeyBase64, salt, iv },
        masterPassword,
    );
    const fingerprint = privateKey.getFingerprint();

    await db.privateKeys.put({
        email,
        encryptedKeyBase64,
        salt,
        iv,
        keyFingerprint: fingerprint,
        createdAt: Date.now(),
        updatedAt: Date.now(),
    });

    return { fingerprint, email };
}

// ─────────────────────────────────────────────────────────────
//  Public keys
// ─────────────────────────────────────────────────────────────

export async function handleGetPublicKey(
    email: string,
): Promise<string | null> {
    const record = await db.publicKeys.get(email.toLowerCase());
    return record?.armoredKey ?? null;
}

export async function handleStorePublicKey(
    email: string,
    armoredKey: string,
    source: "manual" = "manual",
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

// ─────────────────────────────────────────────────────────────
//  List keys
// ─────────────────────────────────────────────────────────────

export async function handleListPrivateKeys(): Promise<KeyInfo[]> {
    const records = await db.privateKeys.toArray();
    return records.map((r) => ({
        email: r.email,
        fingerprint: r.keyFingerprint,
        createdAt: r.createdAt,
    }));
}

export async function handleListPublicKeys(): Promise<KeyInfo[]> {
    const records = await db.publicKeys.toArray();
    return records.map((r) => ({
        email: r.email,
        fingerprint: r.keyFingerprint,
        createdAt: r.createdAt,
        source: r.source,
        verified: r.verified,
    }));
}

// ─────────────────────────────────────────────────────────────
//  Delete keys
// ─────────────────────────────────────────────────────────────

export async function handleDeletePrivateKey(email: string): Promise<void> {
    const emailLower = email.toLowerCase();

    await db.transaction(
        "rw",
        db.privateKeys,
        db.publicKeys,
        db.settings,
        async () => {
            await db.privateKeys.delete(emailLower);
            await db.publicKeys.delete(emailLower);
        },
    );

    removeCachedUnlockedKey(emailLower);
    console.log(
        `[MailShroud] Private key and associated public key deleted for ${emailLower}`,
    );
}

export async function handleDeletePublicKey(email: string): Promise<void> {
    await db.publicKeys.delete(email.toLowerCase());
    console.log(`[MailShroud] Public key deleted for ${email}`);
}

// ─────────────────────────────────────────────────────────────
//  Generate key pair
// ─────────────────────────────────────────────────────────────
export async function handleGenerateKeyPair(params: {
    email: string;
    name?: string;
    masterPassword?: string;
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

    // ── ВИЗНАЧАЄМО МАЙСТЕР-ПАРОЛЬ ─────────────────────────────
    const masterPassword = params.masterPassword || getSessionPassword();
    if (!masterPassword) {
        throw new VaultError(
            VaultErrorCode.VAULT_LOCKED,
            "Vault is locked. Unlock it from the popup before generating keys.",
        );
    }

    // Генерація v6 ключа (curve25519 + AEAD)
    const { privateKey, publicKey } = await generateKeyPair(
        emailLower,
        params.name,
    );

    // Шифрування приватного ключа майстер-паролем (AES-GCM)
    const salt = generateSalt();
    const cryptoKey = await deriveKey(masterPassword, salt);
    const { encryptedData, iv } = await encryptPrivateKey(
        privateKey,
        cryptoKey,
        emailLower,
    );

    const privKeyObj = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const pubKeyObj = await openpgp.readKey({ armoredKey: publicKey });

    // Атомарне збереження в БД
    await db.transaction(
        "rw",
        db.privateKeys,
        db.publicKeys,
        db.settings,
        async () => {
            await db.privateKeys.put({
                email: emailLower,
                encryptedKeyBase64: encryptedData,
                salt,
                iv,
                keyFingerprint: privKeyObj.getFingerprint(),
                createdAt: Date.now(),
                updatedAt: Date.now(),
            });

            await db.publicKeys.put({
                email: emailLower,
                armoredKey: publicKey,
                keyFingerprint: pubKeyObj.getFingerprint(),
                source: "manual",
                verified: true, // self-generated = trusted
                createdAt: Date.now(),
            });
        },
    );

    // ── ІНІЦІАЛІЗАЦІЯ СЕСІЇ (тільки при створенні ПЕРШОГО ключа) ──
    if (params.masterPassword && !getSessionPassword()) {
        setSessionPassword(params.masterPassword);
        cacheUnlockedKey(emailLower, privKeyObj);
        refreshAutoLock();
        startKeepAlive();
        console.log("[MailShroud] Vault session initialized with first key");
    } else {
        // Vault вже був розблокований — просто додаємо новий ключ у кеш
        cacheUnlockedKey(emailLower, privKeyObj);
        refreshAutoLock();
    }

    return {
        privateKeyFingerprint: privKeyObj.getFingerprint(),
        publicKeyArmored: publicKey,
        email: emailLower,
    };
}

export async function handleExportPrivateKey(params: {
    email: string;
    masterPassword?: string;
}): Promise<string> {
    await openpgpReady;
    const emailLower = params.email.toLowerCase();

    const record = await db.privateKeys.get(emailLower);
    if (!record) {
        throw new Error("Приватний ключ для цього email не знайдено");
    }

    const password = params.masterPassword || getSessionPassword();
    if (!password) {
        throw new VaultError(VaultErrorCode.VAULT_LOCKED, "Vault заблоковано");
    }

    try {
        const cryptoKey = await deriveKey(password, record.salt);
        const armoredPrivateKey = await decryptPrivateKey(
            record.encryptedKeyBase64,
            record.iv,
            cryptoKey,
            emailLower,
        );
        return armoredPrivateKey;
    } catch (err) {
        throw new VaultError(
            VaultErrorCode.INVALID_PASSWORD,
            "Невірний майстер-пароль. Доступ відхилено.",
        );
    }
}
