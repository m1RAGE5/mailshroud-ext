import * as openpgp from "openpgp";

/**
 * Ініціалізація OpenPGP.js з безпечними дефолтами.
 * Встановлює суворі налаштування для запобігання known-атакам.
 */
export async function initOpenPGP(): Promise<void> {
    // OpenPGP.js v5+ автоматично ініціалізується при імпорті,
    // WASM завантажується автоматично при необхідності.
    openpgp.config.v6Keys = true;
    openpgp.config.aeadProtect = true;
    openpgp.config.preferredAEADAlgorithm = openpgp.enums.aead.gcm;
    openpgp.config.allowInsecureDecryptionWithSigningKeys = false;
    openpgp.config.allowInsecureVerificationWithReformattedKeys = false;
    openpgp.config.showVersion = false;
    openpgp.config.showComment = false;
}

/**
 * Генерація PGP пари ключів
 */
export async function generateKeyPair(
    email: string,
    name?: string,
): Promise<{
    privateKey: string;
    publicKey: string;
    revocationCertificate: string;
}> {
    // NOTE: Ключ генерується БЕЗ passphrase на рівні OpenPGP.
    // Захист забезпечується виключно через AES-GCM vault (master password).
    // Це дозволяє уникнути подвійного шифрування та спрощує UX.
    const { privateKey, publicKey, revocationCertificate } =
        await openpgp.generateKey({
            type: "curve25519",
            userIDs: [{ name: name ?? email, email }],
            format: "armored",
            config: {
                v6Keys: true,
                aeadProtect: true,
            },
        });
    return { privateKey, publicKey, revocationCertificate };
}

export async function validatePublicKey(
    armoredKey: string,
    expectedEmail: string,
): Promise<openpgp.Key> {
    const key = await openpgp.readKey({ armoredKey });

    if (key.isPrivate()) {
        throw new Error("Refusing to store private key as public");
    }

    if (key.keyPacket.version !== 6) {
        throw new Error(
            `Only v6 keys are supported. Got v${key.keyPacket.version}.`,
        );
    }

    try {
        await key.verifyPrimaryKey();
    } catch (err) {
        throw new Error(
            `Invalid primary key signature: ${(err as Error).message}`,
        );
    }

    if (await key.isRevoked()) {
        throw new Error("Cannot store revoked public key");
    }

    const expiration = await key.getExpirationTime();
    if (
        expiration !== Infinity &&
        expiration !== null &&
        expiration < new Date()
    ) {
        throw new Error("Public key is expired");
    }

    const emailLower = expectedEmail.toLowerCase();
    const hasEmail = key.users.some((user) => {
        const userEmail = user.userID?.email;
        return userEmail?.toLowerCase() === emailLower;
    });

    if (!hasEmail) {
        throw new Error(
            `Public key does not contain expected email: ${expectedEmail}`,
        );
    }

    const primaryKeyAlgo = key.keyPacket.algorithm;
    const allowedAlgorithms = [
        openpgp.enums.publicKey.ed25519,
        openpgp.enums.publicKey.x25519,
    ];

    if (!allowedAlgorithms.includes(primaryKeyAlgo)) {
        throw new Error(
            `Unsupported primary key algorithm. Got: ${primaryKeyAlgo}. ` +
                `Only Ed25519/X25519 (v6) or EdDSA/ECDH (v4) are allowed.`,
        );
    }

    const encryptionKey = await key.getEncryptionKey();
    if (!encryptionKey) {
        throw new Error("No valid encryption subkey found");
    }

    return key;
}

/**
 * Перевірка, що приватний ключ не захищений passphrase (OpenPGP рівень).
 * MailShroud використовує лише AES-GCM vault.
 * Синхронна — openpgp.PrivateKey.isDecrypted() не є async.
 */
export function assertUnprotectedPrivateKey(
    privateKey: openpgp.PrivateKey,
): void {
    if (!privateKey.isDecrypted()) {
        throw new Error(
            "Imported private key is passphrase-protected. MailShroud uses AES-GCM vault only.",
        );
    }
}

/**
 * PBKDF2 derivation key using WebCrypto API
 * @param password - Master password від користувача
 * @param salt - Випадкова сіль (hex string)
 * @returns CryptoKey для AES-GCM (256-bit)
 */
export async function deriveKey(
    password: string,
    salt: string,
): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = hexToBuffer(salt);

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveKey"],
    );

    passwordBuffer.fill(0);

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 600000, // OWASP recommendation 2024
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
    aad: string,
): Promise<{ encryptedData: string; iv: string }> {
    const encoder = new TextEncoder();
    const dataBuffer = new Uint8Array(encoder.encode(armoredKey));
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV для AES-GCM
    const aadBuffer = encoder.encode(aad.toLowerCase());

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aadBuffer },
        key,
        dataBuffer,
    );

    return {
        encryptedData: bufferToBase64(new Uint8Array(encryptedBuffer)),
        iv: bufferToHex(iv),
    };
}

/**
 * Дешифрування приватного ключа за допомогою AES-GCM
 */
export async function decryptPrivateKey(
    encryptedData: string,
    iv: string,
    key: CryptoKey,
    aad: string,
): Promise<string> {
    const dataBuffer = base64ToBuffer(encryptedData);
    const ivBuffer = hexToBuffer(iv);
    const aadBuffer = new TextEncoder().encode(aad.toLowerCase());

    let decryptedBuffer: ArrayBuffer | null = null;
    try {
        decryptedBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer, additionalData: aadBuffer },
            key,
            dataBuffer,
        );
        return new TextDecoder().decode(decryptedBuffer);
    } catch {
        throw new Error("Invalid master password or corrupted vault data.");
    } finally {
        if (decryptedBuffer) new Uint8Array(decryptedBuffer).fill(0);
        dataBuffer.fill(0);
        ivBuffer.fill(0);
    }
}

/**
 * Генерація випадкової солі
 * @returns Hex string
 */
export function generateSalt(): string {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return bufferToHex(salt);
}

/**
 * Генерація випадкового IV для AES-GCM (12 байт)
 * @returns Hex string
 */
export function generateIV(): string {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return bufferToHex(iv);
}

/**
Отримує email з PGP ключа (перший userID)
*/
export function getEmailFromKey(key: openpgp.Key): string | undefined {
    return key.users[0]?.userID?.email ?? undefined;
}

/**
 * Конвертує Uint8Array у Base64 строку безпечно.
 */
function bufferToBase64(buffer: Uint8Array): string {
    const chunks: string[] = [];
    const CHUNK_SIZE = 0x8000;
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
        chunks.push(String.fromCharCode(...buffer.subarray(i, i + CHUNK_SIZE)));
    }
    return btoa(chunks.join(""));
}

/**
 * Конвертує Base64 строку назад у Uint8Array
 */
function base64ToBuffer(b64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Конвертує hex-строку у Uint8Array
 */
function hexToBuffer(hex: string): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

/**
 * Конвертує Uint8Array у hex-строку
 */
function bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
