import Dexie, { type Table } from "dexie";

// ─────────────────────────────────────────────────────────────
//  Records
// ─────────────────────────────────────────────────────────────

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
    | "hkEnabled"
    | `revocation:${string}`;

export interface SettingRecord {
    key: SettingsKey;
    value: string | number | boolean;
}

// ─────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────

/** v6 fingerprint = 32 bytes = 64 hex chars (тільки v6!) */
const V6_FINGERPRINT_LENGTH = 64;
const BASE64_REGEX =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const PGP_PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

// ─────────────────────────────────────────────────────────────
//  Validators
// ─────────────────────────────────────────────────────────────

function validatePrivateKey(obj: Partial<PrivateKeyRecord>): void {
    if (!obj.email?.includes("@")) {
        throw new Error("Invalid email format");
    }
    if (
        !obj.keyFingerprint ||
        obj.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
    ) {
        throw new Error(
            `Invalid v6 fingerprint length: ${obj.keyFingerprint?.length}. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
        );
    }
    if (!BASE64_REGEX.test(obj.encryptedArmoredKey ?? "")) {
        throw new Error("Invalid encrypted key format (not base64)");
    }
}

function validatePublicKey(obj: Partial<PublicKeyRecord>): void {
    if (!obj.armoredKey?.includes(PGP_PUBLIC_KEY_HEADER)) {
        throw new Error("Invalid armored public key");
    }
    if (!obj.email?.includes("@")) {
        throw new Error("Invalid email format");
    }
    if (
        !obj.keyFingerprint ||
        obj.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
    ) {
        throw new Error(
            `Invalid v6 fingerprint length: ${obj.keyFingerprint?.length}. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
        );
    }
}

// ─────────────────────────────────────────────────────────────
//  Database
// ─────────────────────────────────────────────────────────────

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

        // захист від silent corruption
        this.privateKeys.hook("creating", (_pk, obj) =>
            validatePrivateKey(obj),
        );
        this.privateKeys.hook("updating", (mods) => {
            if (Object.keys(mods).length > 0) {
                validatePrivateKey(mods as Partial<PrivateKeyRecord>);
            }
        });

        this.publicKeys.hook("creating", (_pk, obj) => validatePublicKey(obj));
        this.publicKeys.hook("updating", (mods) => {
            if (Object.keys(mods).length > 0) {
                validatePublicKey(mods as Partial<PublicKeyRecord>);
            }
        });
    }
}

export const db = new MailShroudDB();
