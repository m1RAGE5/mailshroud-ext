/**
 * Re-export all database utilities from a single entry point
 */
export {
  db,
  isMasterPasswordSet,
  setMasterPassword,
  getPasswordHint,
  resetMasterPassword,
  storePrivateKey,
  getAllPrivateKeys,
  getPrivateKeyByEmail,
  getPrimaryPrivateKey,
  deletePrivateKey,
  setPrimaryKey,
  storePublicKey,
  getAllPublicKeys,
  getPublicKeyByEmail,
  getPublicKeysByEmails,
  deletePublicKey,
  exportPrivateKey,
  exportAllPublicKeys,
  importPublicKeys
} from './keyDatabase';

export type {
  StoredPrivateKey,
  StoredPublicKey,
  MasterPasswordState
} from './keyDatabase';
