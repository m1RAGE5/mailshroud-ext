import * as openpgp from "openpgp";
import { db } from "~/lib/db";
import {
    getAllCachedKeys,
    getCachedUnlockedKey,
    getEmailFromKey,
    isVaultActuallyUnlocked,
} from "~/lib/crypto";
import type {
    DecryptMessageResult,
    EncryptMessageResult,
} from "~/lib/types/messages";
import { VaultError, VaultErrorCode } from "~/lib/types/error";

// Спільні утиліти та константи (будуть у helpers.ts)
import {
    MAX_MESSAGE_SIZE,
    findPrivateKeyById,
    findPublicKeyById,
    toVaultError,
    openpgpReady,
    type DecryptSignatures,
} from "./helpers";

// Функції життєвого циклу сховища (будуть у vault.ts)
import { refreshAutoLock } from "./vault";

// ─────────────────────────────────────────────────────────────
//  Decrypt
// ─────────────────────────────────────────────────────────────

export async function handleDecryptMessage(
    armoredText: string,
): Promise<DecryptMessageResult> {
    try {
        if (!isVaultActuallyUnlocked()) {
            throw new VaultError(
                VaultErrorCode.VAULT_LOCKED,
                "Vault is locked.",
            );
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

        const WILDCARD_HEX = new Set(["0000000000000000", "00000000"]);
        const hasWildcard = encryptionKeyIds.some((id) =>
            WILDCARD_HEX.has(id.toHex()),
        );

        const matchedKeys = encryptionKeyIds
            .map((id) => findPrivateKeyById(id, snapshot))
            .filter((k): k is openpgp.PrivateKey => !!k);

        const decryptionKeys = [...matchedKeys];

        if (hasWildcard) {
            // Якщо є Wildcard, додаємо ВСІ інші розблоковані ключі з кешу.
            // OpenPGP.js безпечно перебере їх для KEM-дешифрування.
            const matchedFingerprints = new Set(
                decryptionKeys.map((k) => k.getFingerprint()),
            );

            for (const key of snapshot.values()) {
                if (!matchedFingerprints.has(key.getFingerprint())) {
                    decryptionKeys.push(key);
                }
            }
        }

        if (decryptionKeys.length === 0) {
            throw new VaultError(
                VaultErrorCode.NO_MATCHING_KEY,
                encryptionKeyIds.length === 0
                    ? "Message is not encrypted to a PGP key (symmetric-only encryption is not supported)."
                    : "You don't have a private key that can decrypt this message",
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

export async function loadAllPublicKeys(): Promise<openpgp.Key[]> {
    const records = await db.publicKeys.toArray();
    const results = await Promise.allSettled(
        records.map((r) => openpgp.readKey({ armoredKey: r.armoredKey })),
    );

    return results
        .filter((r, index): r is PromiseFulfilledResult<openpgp.Key> => {
            if (r.status === "rejected") {
                if (import.meta.env.DEV) {
                    console.warn(
                        `[MailShroud] Skipping corrupted public key for ${records[index].email}:`,
                        r.reason,
                    );
                }
                return false;
            }
            return true;
        })
        .map((r) => r.value);
}

export async function verifySignatures(
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

export async function handleEncryptMessage(
    text: string,
    recipientEmails: string[],
    senderEmail?: string,
): Promise<EncryptMessageResult> {
    try {
        if (text.length > MAX_MESSAGE_SIZE) {
            throw new Error("Message too large (max 1MB)");
        }

        await openpgpReady;

        if (recipientEmails.length === 0) {
            throw new Error("No recipients specified");
        }

        const encryptionKeys = await Promise.all(
            recipientEmails.map(loadAndValidateRecipientKey),
        );

        const signingKey = pickSigningKey(senderEmail);
        const signingKeys = signingKey ? [signingKey] : [];

        if (signingKey) {
            const senderPubKey = signingKey.toPublic();
            const isAlreadyIncluded = encryptionKeys.some(
                (k) => k.getFingerprint() === senderPubKey.getFingerprint(),
            );

            if (!isAlreadyIncluded) {
                encryptionKeys.push(senderPubKey);
            }
        }

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

export async function loadAndValidateRecipientKey(
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

export function pickSigningKey(
    senderEmail?: string,
): openpgp.PrivateKey | undefined {
    const allOwnKeys = getAllCachedKeys();

    if (senderEmail) {
        const key = getCachedUnlockedKey(senderEmail);
        if (key) return key;
    }

    if (allOwnKeys.size === 1) {
        return allOwnKeys.values().next().value ?? undefined;
    }

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
