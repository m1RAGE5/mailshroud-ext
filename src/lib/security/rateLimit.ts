import { browser } from "wxt/browser";
import { VaultLockTimeoutError } from "../types/error";

interface AttemptState {
    count: number;
    lockedUntil: number;
}

const STORAGE_KEY = "vault_lockout_state";
const SESSION_KEY = "vault_lockout_session";
const PERSISTENT_KEY = "vault_lockout_persistent";

// Прогресивний lockout
export const LOCKOUT_DELAYS = [5_000, 30_000, 120_000, 600_000, 3_600_000];
const MAX_ATTEMPTS_BEFORE_LOCK = 3;

export class VaultLockedError extends Error {
    constructor(public readonly retryAfterMs: number) {
        super(
            `Vault is locked. Try again in ${Math.ceil(retryAfterMs / 1000)}s`,
        );
        this.name = "VaultLockedError";
    }
}

export async function getState(): Promise<Record<string, AttemptState>> {
    const [sessionResult, persistentResult] = await Promise.all([
        browser.storage.session.get(SESSION_KEY),
        browser.storage.local.get(PERSISTENT_KEY),
    ]);

    const session =
        (sessionResult[SESSION_KEY] as Record<string, AttemptState>) ?? {};
    const persistent =
        (persistentResult[PERSISTENT_KEY] as Record<string, AttemptState>) ??
        {};

    const merged: Record<string, AttemptState> = { ...persistent };
    for (const [email, s] of Object.entries(session)) {
        const p = merged[email];
        merged[email] = {
            count: Math.max(p?.count ?? 0, s.count ?? 0),
            lockedUntil: Math.max(p?.lockedUntil ?? 0, s.lockedUntil ?? 0),
        };
    }
    return merged;
}

async function setState(state: Record<string, AttemptState>): Promise<void> {
    await Promise.all([
        browser.storage.session.set({ [SESSION_KEY]: state }),
        browser.storage.local.set({ [PERSISTENT_KEY]: state }),
    ]);
}

let stateLock: Promise<void> = Promise.resolve();

const LOCK_TIMEOUT_MS = 5_000;

function withLock<T>(fn: () => Promise<T>): Promise<T> {
    const next = stateLock.then(fn, fn);
    const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(
            () => reject(new VaultLockTimeoutError(LOCK_TIMEOUT_MS)),
            LOCK_TIMEOUT_MS,
        );
    });

    stateLock = Promise.race([next, timeoutPromise]).then(
        () => {},
        (err) => {
            if (err instanceof VaultLockTimeoutError) {
                console.error(
                    "[MailShroud] Lock timeout — resetting state lock",
                );
            } else {
                console.error("[MailShroud] Lock op failed:", err);
            }
        },
    );

    return Promise.race([next, timeoutPromise]);
}

export async function checkUnlockAttempt(email: string): Promise<void> {
    return withLock(async () => {
        const state = await getState();
        const record = state[email];
        const now = Date.now();

        if (record && record.lockedUntil > 0 && record.lockedUntil <= now) {
            delete state[email];
            await setState(state);
        }

        if (!record) return;

        if (record.lockedUntil > now) {
            throw new VaultLockedError(record.lockedUntil - now);
        }
    });
}

export async function recordFailedAttempt(email: string): Promise<void> {
    return withLock(async () => {
        const state = await getState();
        const now = Date.now();
        const record = state[email] ?? { count: 0, lockedUntil: 0 };
        if (record.lockedUntil > now) {
            return;
        }

        record.count++;
        if (record.count > MAX_ATTEMPTS_BEFORE_LOCK) {
            const delayIndex = Math.min(
                record.count - MAX_ATTEMPTS_BEFORE_LOCK - 1,
                LOCKOUT_DELAYS.length - 1,
            );
            const delay = LOCKOUT_DELAYS[delayIndex]!;
            record.lockedUntil = now + delay;
        }
        state[email] = record;
        await setState(state);
    });
}

export async function resetAttempts(email: string): Promise<void> {
    return withLock(async () => {
        const state = await getState();
        delete state[email];
        await setState(state);
    });
}

export async function resetAllAttempts(): Promise<void> {
    return withLock(async () => {
        await Promise.all([
            browser.storage.session.remove(SESSION_KEY),
            browser.storage.local.remove(PERSISTENT_KEY),
        ]);
    });
}
