// Crypto utilities barrel export
export {
  initOpenPGP,
  generateKeyPair,
  validatePublicKey,
  assertUnprotectedPrivateKey,
  deriveKey,
  encryptPrivateKey,
  decryptPrivateKey,
  generateSalt,
  generateIV,
  getEmailFromKey,
} from "./cryptoService";

export {
  cacheUnlockedKey,
  getCachedUnlockedKey,
  removeCachedUnlockedKey,
  clearSessionCache,
  clearAllUnlockedKeys,
  getAllCachedKeys,
  findKeyByKeyId,
  hasAnyUnlockedKey,
  isVaultActuallyUnlocked,
} from "./sessionState";
