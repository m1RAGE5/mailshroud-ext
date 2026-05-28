import * as openpgp from "openpgp";

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 600_000; // OWASP 2024
const AES_KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96-bit AES-GCM
const SALT_LENGTH = 32; // 256-bit

const OPENPGP_CONFIG = {
    v6Keys: true,
    aeadProtect: true,
    preferredAEADAlgorithm: openpgp.enums.aead.gcm,
    allowInsecureDecryptionWithSigningKeys: false,
    allowInsecureVerificationWithReformattedKeys: false,
    showVersion: false,
    showComment: false,
} as const;

// ─────────────────────────────────────────────────────────────
//  OpenPGP Initialization
// ─────────────────────────────────────────────────────────────

export async function initOpenPGP(): Promise<void> {
    Object.assign(openpgp.config, OPENPGP_CONFIG);
}

// ─────────────────────────────────────────────────────────────
//  Key Generation
// ─────────────────────────────────────────────────────────────

export async function generateKeyPair(
    email: string,
    name?: string,
): Promise<{
    privateKey: string;
    publicKey: string;
    revocationCertificate: string;
}> {
    const result = await openpgp.generateKey({
        type: "curve25519",
        userIDs: [{ name: name ?? email, email }],
        format: "armored",
        config: {
            v6Keys: OPENPGP_CONFIG.v6Keys,
            aeadProtect: OPENPGP_CONFIG.aeadProtect,
        },
    });

    return {
        privateKey: result.privateKey,
        publicKey: result.publicKey,
        revocationCertificate: result.revocationCertificate,
    };
}

// ─────────────────────────────────────────────────────────────
//  Key Validation
// ─────────────────────────────────────────────────────────────

export async function validatePublicKey(
    armoredKey: string,
    expectedEmail: string,
): Promise<openpgp.Key> {
    const key = await openpgp.readKey({ armoredKey });

    assertNotPrivateKey(key);
    assertV6Key(key);
    await assertValidSignature(key);
    await assertNotRevoked(key);
    await assertNotExpired(key);
    assertEmailMatch(key, expectedEmail);
    await assertHasEncryptionSubkey(key);

    return key;
}

function assertNotPrivateKey(key: openpgp.Key): void {
    if (key.isPrivate()) {
        throw new Error("Refusing to store private key as public");
    }
}

function assertV6Key(key: openpgp.Key): void {
    if (key.keyPacket.version !== 6) {
        throw new Error(
            `Only v6 keys are supported. Got v${key.keyPacket.version}.`,
        );
    }
}

async function assertValidSignature(key: openpgp.Key): Promise<void> {
    try {
        await key.verifyPrimaryKey();
    } catch (err) {
        throw new Error(
            `Invalid primary key signature: ${(err as Error).message}`,
        );
    }
}

async function assertNotRevoked(key: openpgp.Key): Promise<void> {
    if (await key.isRevoked()) {
        throw new Error("Cannot store revoked public key");
    }
}

async function assertNotExpired(key: openpgp.Key): Promise<void> {
    const expiration = await key.getExpirationTime();
    if (
        expiration !== Infinity &&
        expiration !== null &&
        expiration < new Date()
    ) {
        throw new Error("Public key is expired");
    }
}

function assertEmailMatch(key: openpgp.Key, expectedEmail: string): void {
    const emailLower = expectedEmail.toLowerCase();
    const hasEmail = key.users.some(
        (user) => user.userID?.email?.toLowerCase() === emailLower,
    );
    if (!hasEmail) {
        throw new Error(
            `Public key does not contain expected email: ${expectedEmail}`,
        );
    }
}

async function assertHasEncryptionSubkey(key: openpgp.Key): Promise<void> {
    const encryptionKey = await key.getEncryptionKey();
    if (!encryptionKey) {
        throw new Error("No valid encryption subkey found");
    }
}

// ─────────────────────────────────────────────────────────────
//  Private Key Assertions
// ─────────────────────────────────────────────────────────────

export function assertUnprotectedPrivateKey(
    privateKey: openpgp.PrivateKey,
): void {
    if (!privateKey.isDecrypted()) {
        throw new Error(
            "Imported private key is passphrase-protected. MailShroud uses AES-GCM vault only.",
        );
    }
}

// ─────────────────────────────────────────────────────────────
//  Key Derivation (PBKDF2)
// ─────────────────────────────────────────────────────────────

export async function deriveKey(
    password: string,
    salt: string,
): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = hexToBuffer(salt);

    try {
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            passwordBuffer,
            "PBKDF2",
            false,
            ["deriveKey"],
        );

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBuffer,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: AES_KEY_LENGTH },
            false,
            ["encrypt", "decrypt"],
        );
    } finally {
        passwordBuffer.fill(0);
        saltBuffer.fill(0);
    }
}

// ─────────────────────────────────────────────────────────────
//  AES-GCM Encryption/Decryption
// ─────────────────────────────────────────────────────────────

export async function encryptPrivateKey(
    armoredKey: string,
    key: CryptoKey,
    aad: string,
): Promise<{ encryptedData: string; iv: string }> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(armoredKey);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const aadBuffer = encoder.encode(aad.toLowerCase());

    try {
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aadBuffer },
            key,
            dataBuffer,
        );

        return {
            encryptedData: bufferToBase64(new Uint8Array(encryptedBuffer)),
            iv: bufferToHex(iv),
        };
    } finally {
        dataBuffer.fill(0);
        aadBuffer.fill(0);
    }
}

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
        if (decryptedBuffer) {
            new Uint8Array(decryptedBuffer).fill(0);
        }
        dataBuffer.fill(0);
        ivBuffer.fill(0);
        aadBuffer.fill(0);
    }
}

// ─────────────────────────────────────────────────────────────
//  Random Generation
// ─────────────────────────────────────────────────────────────

export function generateSalt(): string {
    return bufferToHex(crypto.getRandomValues(new Uint8Array(SALT_LENGTH)));
}

// ─────────────────────────────────────────────────────────────
//  Key Utilities
// ─────────────────────────────────────────────────────────────

export function getEmailFromKey(key: openpgp.Key): string | undefined {
    return key.users[0]?.userID?.email ?? undefined;
}

// ─────────────────────────────────────────────────────────────
//  Buffer Conversions (Optimized)
// ─────────────────────────────────────────────────────────────

function bufferToBase64(buffer: Uint8Array): string {
    // Chunk-based approach for large buffers
    const CHUNK_SIZE = 0x8000; // 32KB
    let binary = "";
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
        const chunk = buffer.subarray(i, i + CHUNK_SIZE);
        binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
    }
    return btoa(binary);
}

function base64ToBuffer(b64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function hexToBuffer(hex: string): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
