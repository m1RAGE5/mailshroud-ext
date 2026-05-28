import { db } from "~/lib/db";
import {
    deriveKey,
    decryptPrivateKey,
    encryptPrivateKey,
    generateSalt,
    cacheUnlockedKey,
    clearSessionCache,
    isVaultActuallyUnlocked,
} from "~/lib/crypto";
import type { UnlockResult } from "~/lib/types/messages";
import {
    checkUnlockAttempt,
    recordFailedAttempt,
    resetAttempts,
    VaultLockedError,
    getState,
} from "~/lib/security/rateLimit";
import { startKeepAlive, stopKeepAlive } from "~/lib/security/vaultKeepAlive";
import { VaultError, VaultErrorCode } from "~/lib/types/error";

// Спільні утиліти (будуть у helpers.ts)
import {
    decryptAndVerifyVaultKey,
    decryptVaultToArmored,
    openpgpReady,
} from "./helpers";

const AUTO_LOCK_MINUTES = 15;

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

export function refreshAutoLock(): void {
    if (!isVaultActuallyUnlocked()) return;
    cancelAutoLock();
    scheduleAutoLock();
}

// ─────────────────────────────────────────────────────────────
//  Unlock
// ─────────────────────────────────────────────────────────────

export async function handleUnlockVault(
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
//  Lock
// ─────────────────────────────────────────────────────────────

export function handleLockVault(): void {
    cancelAutoLock();
    clearSessionCache();
    stopKeepAlive();
    console.log("[MailShroud] Vault locked");
}

// ─────────────────────────────────────────────────────────────
//  Change master password
// ─────────────────────────────────────────────────────────────

export async function handleChangeMasterPassword(
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
