import Dexie, { type Table } from "dexie";

// ─────────────────────────────────────────────────────────────
//  Records
// ─────────────────────────────────────────────────────────────
export interface PrivateKeyRecord {
    email: string;
    encryptedKeyBase64: string;
    salt: string;
    iv: string;
    keyFingerprint: string;
    createdAt: number;
    updatedAt: number;
}

export interface PublicKeyRecord {
    email: string;
    armoredKey: string;
    keyFingerprint: string;
    source: "manual";
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
//  Validators (Тільки для створення нових записів!)
// ─────────────────────────────────────────────────────────────
function validatePrivateKey(obj: Partial<PrivateKeyRecord>): void {
    if (!obj.email?.includes("@")) throw new Error("Invalid email format");
    if (
        !obj.keyFingerprint ||
        obj.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
    ) {
        throw new Error(
            `Invalid v6 fingerprint length. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
        );
    }
    if (!obj.encryptedKeyBase64 || !BASE64_REGEX.test(obj.encryptedKeyBase64)) {
        throw new Error("Invalid encrypted key format (not base64)");
    }
}

function validatePublicKey(obj: Partial<PublicKeyRecord>): void {
    if (!obj.armoredKey?.includes(PGP_PUBLIC_KEY_HEADER))
        throw new Error("Invalid armored public key");
    if (!obj.email?.includes("@")) throw new Error("Invalid email format");
    if (
        !obj.keyFingerprint ||
        obj.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
    ) {
        throw new Error(
            `Invalid v6 fingerprint length. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
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

        // ── creating: Валідуємо повний об'єкт ──
        this.privateKeys.hook("creating", (_pk, obj) =>
            validatePrivateKey(obj),
        );
        this.publicKeys.hook("creating", (_pk, obj) => validatePublicKey(obj));

        // ── updating: Валідуємо ТІЛЬКИ поля, які змінюються (Partial Update) ──
        // ✅ Явна анотація типу Partial<...Record> вирішує помилку "Property does not exist on type 'Object'"
        this.privateKeys.hook("updating", (mods: Partial<PrivateKeyRecord>) => {
            if (mods.email !== undefined && !mods.email.includes("@")) {
                throw new Error("Invalid email format");
            }
            if (
                mods.keyFingerprint !== undefined &&
                mods.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
            ) {
                throw new Error(
                    `Invalid v6 fingerprint length: ${mods.keyFingerprint.length}. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
                );
            }
            if (
                mods.encryptedKeyBase64 !== undefined &&
                !BASE64_REGEX.test(mods.encryptedKeyBase64)
            ) {
                throw new Error("Invalid encrypted key format (not base64)");
            }
        });

        this.publicKeys.hook("updating", (mods: Partial<PublicKeyRecord>) => {
            if (
                mods.armoredKey !== undefined &&
                !mods.armoredKey.includes(PGP_PUBLIC_KEY_HEADER)
            ) {
                throw new Error("Invalid armored public key");
            }
            if (mods.email !== undefined && !mods.email.includes("@")) {
                throw new Error("Invalid email format");
            }
            if (
                mods.keyFingerprint !== undefined &&
                mods.keyFingerprint.length !== V6_FINGERPRINT_LENGTH
            ) {
                throw new Error(
                    `Invalid v6 fingerprint length: ${mods.keyFingerprint.length}. Expected ${V6_FINGERPRINT_LENGTH} hex chars.`,
                );
            }
        });
    }
}

export const db = new MailShroudDB();
