import { defineExtensionMessaging, type Message } from "@webext-core/messaging";
import * as openpgp from "openpgp";
import { db } from "~/lib/db/database";
import {
  deriveKey,
  decryptPrivateKey,
  encryptPrivateKey,
  generateSalt,
  initOpenPGP,
} from "~/lib/crypto/cryptoService";
import {
  cacheUnlockedKey,
  getCachedUnlockedKey,
  clearSessionCache,
} from "~/lib/crypto/sessionState";
import type { MailShroudMessages } from "~/lib/types/messages";

// Створюємо type-safe messenger
const messenger = defineExtensionMessaging<MailShroudMessages>();

export default defineBackground(() => {
  console.log("MailShroud Background Service Worker started", {
    id: browser.runtime.id,
  });

  // Ініціалізація OpenPGP.js при старті
  initOpenPGP().catch((err) => {
    console.error("Failed to initialize OpenPGP:", err);
  });

  // Реєстрація message handler'ів
  setupMessageHandlers();
});

function setupMessageHandlers() {
  // Реєструємо кожен тип повідомлення окремо для type-safety
  messenger.onMessage("decryptMessage", async (message) => {
    return await handleDecryptMessage(message.data);
  });

  messenger.onMessage("encryptMessage", async (message) => {
    const [text, recipientEmails] = message.data as [string, string[]];
    return await handleEncryptMessage(text, recipientEmails);
  });

  messenger.onMessage("unlockVault", async (message) => {
    return await handleUnlockVault(message.data as string);
  });

  messenger.onMessage("lockVault", async () => {
    await handleLockVault();
    return undefined as never;
  });

  messenger.onMessage("storePrivateKey", async (message) => {
    const [email, encryptedArmoredKey, salt, iv] = message.data as [
      string,
      string,
      string,
      string,
    ];
    await handleStorePrivateKey(email, encryptedArmoredKey, salt, iv);
    return undefined as never;
  });

  messenger.onMessage("getPublicKey", async (message) => {
    return await handleGetPublicKey(message.data as string);
  });

  messenger.onMessage("storePublicKey", async (message) => {
    const [email, armoredKey] = message.data as [string, string];
    await handleStorePublicKey(email, armoredKey);
    return undefined as never;
  });

  messenger.onMessage("isVaultUnlocked", async () => {
    return await handleIsVaultUnlocked();
  });
}

/**
 * Розшифрування PGP повідомлення
 */
async function handleDecryptMessage(armoredText: string): Promise<string> {
  try {
    const message = await openpgp.readMessage({ armoredMessage: armoredText });

    // Отримуємо всі ключі з сесії для спроби розшифрування
    const sessionKeys = await getCachedUnlockedKeysFromSession();

    if (sessionKeys.length === 0) {
      throw new Error("Vault is locked. No private keys available.");
    }

    // Спробуємо розшифрувати кожним доступним ключем
    let decrypted: Awaited<ReturnType<typeof openpgp.decrypt>> | null = null;
    let lastError: Error | null = null;

    for (const armoredKey of sessionKeys) {
      try {
        const privateKey = await openpgp.readKey({ armoredKey });

        decrypted = await openpgp.decrypt({
          message,
          decryptionKeys: privateKey as unknown as openpgp.PrivateKey,
        });

        break; // Успішно розшифровано
      } catch (err) {
        lastError = err as Error;
        continue; // Спробуємо наступний ключ
      }
    }

    if (!decrypted) {
      throw lastError || new Error("Failed to decrypt with any available key");
    }

    return decrypted.data as string;
  } catch (error) {
    console.error("Decryption failed:", error);
    throw error;
  }
}

/**
 * Шифрування повідомлення для отримувачів
 */
async function handleEncryptMessage(
  text: string,
  recipientEmails: string[],
): Promise<string> {
  try {
    if (recipientEmails.length === 0) {
      throw new Error("No recipients specified");
    }

    const publicKeys: openpgp.Key[] = [];

    for (const email of recipientEmails) {
      const armoredKey = await db.publicKeys.get(email);

      if (!armoredKey) {
        throw new Error(`Public key not found for ${email}`);
      }

      const publicKey = await openpgp.readKey({
        armoredKey: armoredKey.armoredKey,
      });
      publicKeys.push(publicKey);
    }

    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ text }),
      encryptionKeys: publicKeys,
    });

    return encrypted as string;
  } catch (error) {
    console.error("Encryption failed:", error);
    throw error;
  }
}

/**
 * Розблокування vault з Master Password
 */
async function handleUnlockVault(masterPassword: string): Promise<boolean> {
  try {
    // Отримуємо всі приватні ключі з БД
    const allPrivateKeys = await db.privateKeys.toArray();

    if (allPrivateKeys.length === 0) {
      console.warn("No private keys found in vault");
      return false;
    }

    let unlockedCount = 0;

    for (const keyRecord of allPrivateKeys) {
      try {
        const cryptoKey = await deriveKey(masterPassword, keyRecord.salt);
        const armoredKey = await decryptPrivateKey(
          keyRecord.encryptedArmoredKey,
          keyRecord.iv,
          cryptoKey,
        );

        // Зберігаємо у session storage
        await cacheUnlockedKey(keyRecord.email, armoredKey);
        unlockedCount++;
      } catch (err) {
        console.warn(`Failed to unlock key for ${keyRecord.email}:`, err);
        // Продовжуємо з іншими ключами
      }
    }

    return unlockedCount > 0;
  } catch (error) {
    console.error("Vault unlock failed:", error);
    throw error;
  }
}

/**
 * Блокування vault (очищення session cache)
 */
async function handleLockVault(): Promise<void> {
  await clearSessionCache();
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
): Promise<void> {
  await db.privateKeys.put({
    email,
    encryptedArmoredKey,
    salt,
    iv,
  });
  console.log(`Private key stored for ${email}`);
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
  await db.publicKeys.put({
    email,
    armoredKey,
  });
  console.log(`Public key stored for ${email}`);
}

/**
 * Перевірка чи vault розблокований
 */
async function handleIsVaultUnlocked(): Promise<boolean> {
  const sessionKeys = await getCachedUnlockedKeysFromSession();
  return sessionKeys.length > 0;
}

/**
 * Допоміжна функція для отримання всіх ключів з сесії
 */
async function getCachedUnlockedKeysFromSession(): Promise<string[]> {
  const sessionData = await browser.storage.session.get("session:unlockedKeys");
  const keysMap = sessionData["session:unlockedKeys"] as
    | Record<string, { armoredKey: string }>
    | undefined;

  if (!keysMap) return [];

  return Object.values(keysMap).map((k) => k.armoredKey);
}
