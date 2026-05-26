import Dexie, { type Table } from "dexie";

export interface PrivateKeyRecord {
  id?: number;
  email: string;
  encryptedArmoredKey: string;
  salt: string;
  iv: string;
}

export interface PublicKeyRecord {
  email: string;
  armoredKey: string;
}

export class MailShroudDB extends Dexie {
  privateKeys!: Table<PrivateKeyRecord, number>;
  publicKeys!: Table<PublicKeyRecord, string>;

  constructor() {
    super("MailShroudDB");
    this.version(1).stores({
      privateKeys: "++id, email",
      publicKeys: "email",
    });
  }
}

export const db = new MailShroudDB();
