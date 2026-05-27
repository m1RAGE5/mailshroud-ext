export enum VaultErrorCode {
    LOCKED = "VAULT_LOCKED",
    NO_MATCHING_KEY = "NO_MATCHING_KEY",
    RATE_LIMITED = "VAULT_RATE_LIMITED",
    INVALID_PASSWORD = "INVALID_PASSWORD",
    CORRUPTED_DATA = "CORRUPTED_DATA",
}

export class VaultError extends Error {
    constructor(
        public readonly code: VaultErrorCode,
        message: string,
        public readonly retryAfterMs?: number,
    ) {
        super(message);
        this.name = "VaultError";
    }
}

export class VaultLockTimeoutError extends Error {
    constructor(timeoutMs?: number) {
        const msg = timeoutMs
            ? `Vault lock acquisition timed out after ${timeoutMs}ms. Please try again.`
            : "Vault lock acquisition timed out. Please try again.";
        super(msg);
        this.name = "VaultLockTimeoutError";
    }
}
