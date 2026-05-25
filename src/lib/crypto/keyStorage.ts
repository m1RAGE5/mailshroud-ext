/**
 * Crypto utilities for secure key storage using WebCrypto API
 * 
 * Security Model:
 * - Master Password is never stored
 * - Private PGP keys are encrypted with AES-GCM (256-bit)
 * - Encryption key is derived from Master Password using PBKDF2
 * - Salt is randomly generated per key and stored alongside encrypted data
 */

import * as openpgp from 'openpgp';

// Constants for key derivation
const PBKDF2_ITERATIONS = 100000; // OWASP recommended minimum
const SALT_LENGTH = 16; // 128 bits
const KEY_LENGTH = 32; // 256 bits for AES-GCM

/**
 * Generate a cryptographically secure random salt
 */
export async function generateSalt(): Promise<Uint8Array> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  return salt;
}

/**
 * Derive an AES key from the master password using PBKDF2
 * 
 * @param password - The master password
 * @param salt - Random salt for this derivation
 * @returns CryptoKey for AES-GCM encryption/decryption
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  // Import password as raw key material for PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  // Derive AES-GCM key
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data using AES-GCM
 * 
 * @param data - Data to encrypt (string or Uint8Array)
 * @param key - AES key derived from master password
 * @param iv - Initialization vector (will be generated if not provided)
 * @returns Object containing encrypted data and IV
 */
export async function encryptData(
  data: Uint8Array,
  key: CryptoKey,
  iv?: Uint8Array
): Promise<{ encrypted: ArrayBuffer; iv: Uint8Array }> {
  const initializationVector = iv || crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: initializationVector
    },
    key,
    data
  );
  
  return { encrypted, iv: initializationVector };
}

/**
 * Decrypt data using AES-GCM
 * 
 * @param encrypted - Encrypted data
 * @param key - AES key derived from master password
 * @param iv - Initialization vector used during encryption
 * @returns Decrypted data as Uint8Array
 */
export async function decryptData(
  encrypted: ArrayBuffer,
  key: CryptoKey,
  iv: Uint8Array
): Promise<Uint8Array> {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encrypted
  );
  
  return new Uint8Array(decrypted);
}

/**
 * Convert ArrayBuffer to base64 string for storage
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert base64 string back to Uint8Array
 */
export function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypt a PGP private key armor string
 * 
 * @param armoredPrivateKey - The PGP armored private key
 * @param masterPassword - User's master password
 * @returns Encrypted key data ready for storage
 */
export async function encryptPrivateKey(
  armoredPrivateKey: string,
  masterPassword: string
): Promise<{ encrypted: string; salt: string; iv: string }> {
  const salt = await generateSalt();
  const key = await deriveKey(masterPassword, salt);
  
  const encoder = new TextEncoder();
  const data = encoder.encode(armoredPrivateKey);
  
  const { encrypted, iv } = await encryptData(data, key);
  
  return {
    encrypted: arrayBufferToBase64(encrypted),
    salt: arrayBufferToBase64(salt),
    iv: arrayBufferToBase64(iv)
  };
}

/**
 * Decrypt a PGP private key armor string
 * 
 * @param encryptedData - Encrypted key data from storage
 * @param masterPassword - User's master password
 * @returns Decrypted armored private key
 */
export async function decryptPrivateKey(
  encryptedData: { encrypted: string; salt: string; iv: string },
  masterPassword: string
): Promise<string> {
  const salt = base64ToArrayBuffer(encryptedData.salt);
  const iv = base64ToArrayBuffer(encryptedData.iv);
  const key = await deriveKey(masterPassword, salt);
  
  const encrypted = base64ToArrayBuffer(encryptedData.encrypted);
  const decrypted = await decryptData(encrypted.buffer, key, iv);
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Generate a new PGP key pair
 * 
 * @param userIdentity - User ID (name and email)
 * @param passphrase - Passphrase to protect the private key (optional, we store it encrypted anyway)
 * @returns Generated key pair
 */
export async function generateKeyPair(
  userIdentity: { name: string; email: string },
  passphrase?: string
): Promise<{ publicKey: string; privateKey: string }> {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc', // Use ECC for better security/performance
    curve: 'curve25519', // Modern elliptic curve
    userIDs: [{ name: userIdentity.name, email: userIdentity.email }],
    passphrase: passphrase,
    format: 'armored'
  });
  
  return { publicKey, privateKey };
}

/**
 * Encrypt a message for multiple recipients
 * 
 * @param message - Plain text message
 * @param publicKeys - Armored public keys of all recipients
 * @returns Encrypted PGP message
 */
export async function encryptMessage(
  message: string,
  publicKeys: string[]
): Promise<string> {
  const pgpPublicKeys = await Promise.all(
    publicKeys.map(key => openpgp.readKey({ armoredKey: key }))
  );
  
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: pgpPublicKeys
  });
  
  return encrypted as string;
}

/**
 * Decrypt a PGP message
 * 
 * @param encryptedMessage - Encrypted PGP message
 * @param privateKey - Armored private key
 * @param passphrase - Passphrase for the private key
 * @returns Decrypted message
 */
export async function decryptMessage(
  encryptedMessage: string,
  privateKey: string,
  passphrase?: string
): Promise<string> {
  const pgpPrivateKey = await openpgp.readPrivateKey({ armoredKey: privateKey });
  
  // If passphrase is provided, decrypt the private key first
  let decryptionKey = pgpPrivateKey;
  if (passphrase) {
    decryptionKey = await openpgp.decryptKey({
      privateKey: pgpPrivateKey,
      passphrase
    });
  }
  
  const message = await openpgp.readMessage({ armoredMessage: encryptedMessage });
  const { data } = await openpgp.decrypt({
    message,
    decryptionKeys: decryptionKey
  });
  
  return data as string;
}

/**
 * Extract PGP encrypted blocks from text
 * Returns array of PGP messages found in the text
 */
export function extractPGPBlocks(text: string): string[] {
  const pgpBlockRegex = /-----BEGIN PGP MESSAGE-----[\s\S]*?-----END PGP MESSAGE-----/g;
  const matches = text.match(pgpBlockRegex);
  return matches || [];
}

/**
 * Check if text contains PGP encrypted content
 */
export function containsPGP(text: string): boolean {
  return extractPGPBlocks(text).length > 0;
}
