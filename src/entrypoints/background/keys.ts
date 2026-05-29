import * as openpgp from "openpgp";
import { db } from "~/lib/db";
import {
    deriveKey,
    encryptPrivateKey,
    generateSalt,
    generateKeyPair,
    validatePublicKey,
    removeCachedUnlockedKey,
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
    await db.transaction("rw", db.privateKeys, db.settings, async () => {
        await db.privateKeys.delete(emailLower);
        await db.settings.delete(`revocation:${emailLower}`);
    });
    removeCachedUnlockedKey(emailLower);
    console.log(`[MailShroud] Private key deleted for ${emailLower}`);
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
                encryptedKeyBase64: encryptedData,
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
//  Export revocation certificate
// ─────────────────────────────────────────────────────────────

export async function handleExportRevocationCertificate(
    email: string,
): Promise<string | null> {
    const emailLower = email.toLowerCase();
    const record = await db.settings.get(`revocation:${emailLower}`);
    if (!record || typeof record.value !== "string") return null;
    return record.value;
}
