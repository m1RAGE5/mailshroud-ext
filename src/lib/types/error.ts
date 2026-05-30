// ─────────────────────────────────────────────────────────────
//  Error Codes (для type-safe обробки в UI)
// ─────────────────────────────────────────────────────────────

export enum VaultErrorCode {
    // Auth / Vault state
    VAULT_LOCKED = "VAULT_LOCKED",
    INVALID_PASSWORD = "INVALID_PASSWORD",
    RATE_LIMITED = "RATE_LIMITED",

    // Data integrity
    CORRUPTED_DATA = "CORRUPTED_DATA",
    VAULT_LOCK_TIMEOUT = "VAULT_LOCK_TIMEOUT",

    // Key operations
    NO_MATCHING_KEY = "NO_MATCHING_KEY",
    KEY_NOT_FOUND = "KEY_NOT_FOUND",
    KEY_EXPIRED = "KEY_EXPIRED",
    KEY_REVOKED = "KEY_REVOKED",
    KEY_ALREADY_EXISTS = "KEY_ALREADY_EXISTS",
    UNSUPPORTED_KEY_VERSION = "UNSUPPORTED_KEY_VERSION",

    // Signature verification
    SIGNATURE_INVALID = "SIGNATURE_INVALID",
    SIGNATURE_MISSING = "SIGNATURE_MISSING",
    SIGNER_UNKNOWN = "SIGNER_UNKNOWN",
}

// ─────────────────────────────────────────────────────────────
//  Base Vault Error
// ─────────────────────────────────────────────────────────────

/**
 * Базовий клас помилок MailShroud vault.
 * Має `toJSON()` для коректної serialization через @webext-core/messaging
 * (Error об'єкти втрачають поля при передачі між content script ↔ background).
 */
export class VaultError extends Error {
    constructor(
        public readonly code: VaultErrorCode,
        message: string,
        public readonly retryAfterMs?: number,
    ) {
        super(message);
        this.name = "VaultError";
        // Збереження stack trace для debugging
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, VaultError);
        }
    }

    toJSON(): {
        name: string;
        code: VaultErrorCode;
        message: string;
        retryAfterMs?: number;
    } {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            retryAfterMs: this.retryAfterMs,
        };
    }

    /** Deserialization з messaging API */
    static fromJSON(obj: {
        code: VaultErrorCode;
        message: string;
        retryAfterMs?: number;
    }): VaultError {
        return new VaultError(obj.code, obj.message, obj.retryAfterMs);
    }
}

// ─────────────────────────────────────────────────────────────
//  Specialized Errors
// ─────────────────────────────────────────────────────────────

/**
 * Кинутий коли lock на vault state не може бути отриманий за timeout.
 * Захист від race conditions при одночасних unlock спробах.
 */
export class VaultLockTimeoutError extends VaultError {
    constructor(timeoutMs?: number) {
        super(
            VaultErrorCode.VAULT_LOCK_TIMEOUT,
            timeoutMs
                ? `Vault lock acquisition timed out after ${timeoutMs}ms. Please try again.`
                : "Vault lock acquisition timed out. Please try again.",
        );
        this.name = "VaultLockTimeoutError";
    }
}
