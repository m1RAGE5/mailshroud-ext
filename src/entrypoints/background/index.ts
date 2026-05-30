import { defineExtensionMessaging } from "@webext-core/messaging";
import { db } from "~/lib/db";
import { isVaultActuallyUnlocked, clearSessionCache } from "~/lib/crypto";
import { messenger } from "~/lib/messaging";
import { stopKeepAlive } from "~/lib/security/vaultKeepAlive";
import { VaultError, VaultErrorCode } from "~/lib/types/error";
import type { MailShroudMessages } from "~/lib/types/messages";

// ── Обробники з інших модулів ──────────────────────────────
import { handleDecryptMessage, handleEncryptMessage } from "./crypto";
import {
    handleUnlockVault,
    handleLockVault,
    handleChangeMasterPassword,
} from "./vault";
import {
    handleStorePrivateKey,
    handleGetPublicKey,
    handleStorePublicKey,
    handleListPrivateKeys,
    handleListPublicKeys,
    handleDeletePrivateKey,
    handleDeletePublicKey,
    handleGenerateKeyPair,
    handleExportPrivateKey,
} from "./keys";

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

    browser.runtime.onStartup.addListener(() => {
        console.log("[MailShroud] Browser startup — vault locked");
        handleLockVault();
    });

    browser.runtime.onInstalled.addListener((details) => {
        if (details.reason === "install" || details.reason === "update") {
            handleLockVault();
        }
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
            encryptedKeyBase64,
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
            encryptedKeyBase64,
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
    messenger.onMessage("exportPrivateKey", (m) =>
        handleExportPrivateKey(m.data),
    );

    // ── Public keys ────────────────────────────────────────
    messenger.onMessage("getPublicKey", (m) => handleGetPublicKey(m.data));
    messenger.onMessage("storePublicKey", (m) =>
        handleStorePublicKey(
            m.data.email,
            m.data.armoredKey,
            m.data.source ?? "manual",
            m.data.verified,
        ),
    );
    messenger.onMessage("listPublicKeys", () => handleListPublicKeys());
    messenger.onMessage("deletePublicKey", (m) =>
        handleDeletePublicKey(m.data),
    );
}
