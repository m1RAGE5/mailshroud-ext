import Dexie, { type Table } from "dexie";

export interface PrivateKeyRecord {
    email: string;
    encryptedArmoredKey: string;
    salt: string;
    iv: string;
    keyFingerprint: string;
    createdAt: number;
    updatedAt: number;
}

export type PublicKeySource =
    | "wkd"
    | "hkp"
    | "autocrypt"
    | "manual"
    | "key-gossip";

export interface PublicKeyRecord {
    email: string;
    armoredKey: string;
    keyFingerprint: string;
    source: PublicKeySource;
    verified: boolean;
    createdAt: number;
    lastUsedAt?: number;
}

export type SettingsKey =
    | "autoLockMinutes"
    | "preferredKeyServer"
    | "wkdEnabled"
    | "hkEnabled";

export interface SettingRecord {
    key: SettingsKey;
    value: string | number | boolean;
}

export class MailShroudDB extends Dexie {
    privateKeys!: Table<PrivateKeyRecord, string>;
    publicKeys!: Table<PublicKeyRecord, string>;
    settings!: Table<SettingRecord, string>;

    constructor() {
        super("MailShroudDB");

        this.version(1).stores({
            privateKeys: "&email",
            publicKeys: "&email",
            settings: "&key",
        });

        this.privateKeys.hook("creating", (primKey, obj) => {
            if (!obj.email?.includes("@")) {
                throw new Error("Invalid email format");
            }
            if (
                !obj.keyFingerprint ||
                (obj.keyFingerprint.length !== 64 &&
                    obj.keyFingerprint.length !== 40)
            ) {
                throw new Error(
                    `Invalid key fingerprint length: ${obj.keyFingerprint?.length}. ` +
                        `Expected 64 (v6) or 40 (v4) hex characters.`,
                );
            }
            if (!/^[A-Za-z0-9+/=]+$/.test(obj.encryptedArmoredKey)) {
                throw new Error("Invalid encrypted key format");
            }
        });

        this.publicKeys.hook("creating", (primKey, obj) => {
            if (
                !obj.armoredKey.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            ) {
                throw new Error("Invalid armored public key");
            }
        });
    }
}

export const db = new MailShroudDB();
