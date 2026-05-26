import * as openpgp from "openpgp";

/**
 * Ініціалізація OpenPGP.js
 */
export async function initOpenPGP(): Promise<void> {
  // OpenPGP.js v5+ автоматично ініціалізується при імпорті,
  // WASM завантажується автоматично при необхідності
}

/**
 * PBKDF2 derivation key using WebCrypto API
 * @param password - Master password від користувача
 * @param salt - Випадкова сіль (hex string)
 * @returns CryptoKey для AES-GCM
 */
export async function deriveKey(
  password: string,
  salt: string,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Конвертуємо hex соль у ArrayBuffer
  const saltBuffer = Uint8Array.from(
    salt.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [],
  );

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 600000, // 600k ітерацій для безпеки
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Шифрування приватного ключа за допомогою AES-GCM
 * @param armoredKey - Приватний ключ у вигляді ASCII-armored строки
 * @param key - CryptoKey отриманий через deriveKey
 * @returns Об'єкт з encryptedData (base64) та iv (hex)
 */
export async function encryptPrivateKey(
  armoredKey: string,
  key: CryptoKey,
): Promise<{ encryptedData: string; iv: string }> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(armoredKey);

  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV для AES-GCM

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    dataBuffer,
  );

  // Конвертуємо у base64 для зберігання
  const encryptedData = btoa(
    String.fromCharCode(...new Uint8Array(encryptedBuffer)),
  );
  const ivHex = Array.from(iv)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { encryptedData, iv: ivHex };
}

/**
 * Дешифрування приватного ключа за допомогою AES-GCM
 * @param encryptedData - Зашифровані дані (base64)
 * @param iv - Initialization vector (hex string)
 * @param key - CryptoKey отриманий через deriveKey
 * @returns Розшифрований armored ключ (строка)
 */
export async function decryptPrivateKey(
  encryptedData: string,
  iv: string,
  key: CryptoKey,
): Promise<string> {
  // Конвертуємо base64 назад у ArrayBuffer
  const binaryString = atob(encryptedData);
  const len = binaryString.length;
  const dataBuffer = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    dataBuffer[i] = binaryString.charCodeAt(i);
  }

  // Конвертуємо hex IV у Uint8Array
  const ivBuffer = Uint8Array.from(
    iv.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [],
  );

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivBuffer,
    },
    key,
    dataBuffer,
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

/**
 * Генерація випадкової солі (16 байт)
 * @returns Hex string
 */
export function generateSalt(): string {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(salt)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
