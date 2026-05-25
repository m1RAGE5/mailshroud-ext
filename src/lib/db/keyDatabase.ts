/**
 * IndexedDB database for storing PGP keys securely
 * Uses Dexie.js for a cleaner API
 */

import Dexie, { Table } from 'dexie';

/**
 * Interface for stored private key
 * The actual key material is encrypted using WebCrypto AES-GCM
 */
export interface StoredPrivateKey {
  id?: number;
  email: string;
  name: string;
  publicKey: string; // Public key in armored format (not encrypted)
  encryptedPrivateKey: string; // Encrypted private key (base64)
  salt: string; // Salt for key derivation (base64)
  iv: string; // IV for AES-GCM (base64)
  createdAt: Date;
  isPrimary: boolean; // Whether this is the primary key for the user
}

/**
 * Interface for stored public key of a contact
 */
export interface StoredPublicKey {
  id?: number;
  email: string;
  name: string;
  publicKey: string; // Public key in armored format
  createdAt: Date;
  source: 'import' | 'extracted' | 'keyserver'; // How we got this key
}

/**
 * Interface for master password hint (optional)
 * Never store the actual password!
 */
export interface MasterPasswordState {
  id: number; // Always 1, singleton
  isSet: boolean;
  hint?: string; // Optional hint to help remember password
  createdAt: Date;
}

/**
 * Mailshroud Database
 */
class MailshroudDB extends Dexie {
  privateKeys!: Table<StoredPrivateKey, number>;
  publicKeys!: Table<StoredPublicKey, number>;
  passwordState!: Table<MasterPasswordState, number>;

  constructor() {
    super('MailshroudDB');
    
    this.version(1).stores({
      privateKeys: '++id, email, isPrimary',
      publicKeys: '++id, email',
      passwordState: 'id'
    });
  }
}

export const db = new MailshroudDB();

/**
 * Check if master password has been set
 */
export async function isMasterPasswordSet(): Promise<boolean> {
  const state = await db.passwordState.get(1);
  return state?.isSet ?? false;
}

/**
 * Set master password state (called after user creates master password)
 */
export async function setMasterPassword(hint?: string): Promise<void> {
  await db.passwordState.put({
    id: 1,
    isSet: true,
    hint,
    createdAt: new Date()
  });
}

/**
 * Get password hint (if set)
 */
export async function getPasswordHint(): Promise<string | undefined> {
  const state = await db.passwordState.get(1);
  return state?.hint;
}

/**
 * Reset master password state (for recovery scenarios)
 * Note: This will make all stored private keys inaccessible!
 */
export async function resetMasterPassword(): Promise<void> {
  await db.transaction('rw', db.passwordState, db.privateKeys, async () => {
    await db.passwordState.delete(1);
    await db.privateKeys.clear();
  });
}

/**
 * Store an encrypted private key
 */
export async function storePrivateKey(
  keyData: Omit<StoredPrivateKey, 'id' | 'createdAt'>
): Promise<number> {
  const id = await db.privateKeys.add({
    ...keyData,
    createdAt: new Date()
  });
  return id;
}

/**
 * Get all stored private keys
 */
export async function getAllPrivateKeys(): Promise<StoredPrivateKey[]> {
  return db.privateKeys.toArray();
}

/**
 * Get private key by email
 */
export async function getPrivateKeyByEmail(email: string): Promise<StoredPrivateKey | undefined> {
  return db.privateKeys.where('email').equals(email).first();
}

/**
 * Get primary private key
 */
export async function getPrimaryPrivateKey(): Promise<StoredPrivateKey | undefined> {
  return db.privateKeys.where('isPrimary').equals(true).first();
}

/**
 * Delete a private key
 */
export async function deletePrivateKey(id: number): Promise<void> {
  await db.privateKeys.delete(id);
}

/**
 * Set a key as primary
 */
export async function setPrimaryKey(id: number): Promise<void> {
  await db.transaction('rw', db.privateKeys, async () => {
    await db.privateKeys.toCollection().modify({ isPrimary: false });
    await db.privateKeys.update(id, { isPrimary: true });
  });
}

/**
 * Store a public key
 */
export async function storePublicKey(
  keyData: Omit<StoredPublicKey, 'id' | 'createdAt'>
): Promise<number> {
  // Check if we already have a key for this email
  const existing = await db.publicKeys.where('email').equals(keyData.email).first();
  if (existing) {
    await db.publicKeys.update(existing.id!, {
      publicKey: keyData.publicKey,
      name: keyData.name,
      source: keyData.source
    });
    return existing.id!;
  }
  
  return db.publicKeys.add({
    ...keyData,
    createdAt: new Date()
  });
}

/**
 * Get all stored public keys
 */
export async function getAllPublicKeys(): Promise<StoredPublicKey[]> {
  return db.publicKeys.toArray();
}

/**
 * Get public key by email
 */
export async function getPublicKeyByEmail(email: string): Promise<StoredPublicKey | undefined> {
  return db.publicKeys.where('email').equals(email).first();
}

/**
 * Get public keys for multiple emails
 */
export async function getPublicKeysByEmails(emails: string[]): Promise<StoredPublicKey[]> {
  return db.publicKeys.where('email').anyOf(emails).toArray();
}

/**
 * Delete a public key
 */
export async function deletePublicKey(id: number): Promise<void> {
  await db.publicKeys.delete(id);
}

/**
 * Export private key data for backup
 */
export async function exportPrivateKey(id: number): Promise<StoredPrivateKey | null> {
  return db.privateKeys.get(id) || null;
}

/**
 * Export all public keys
 */
export async function exportAllPublicKeys(): Promise<StoredPublicKey[]> {
  return db.publicKeys.toArray();
}

/**
 * Import public keys from backup
 */
export async function importPublicKeys(keys: StoredPublicKey[]): Promise<void> {
  await db.publicKeys.bulkAdd(keys);
}
