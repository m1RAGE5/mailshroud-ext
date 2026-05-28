import { browser } from "wxt/browser";
import { VaultLockTimeoutError } from "../types/error";

// ─────────────────────────────────────────────────────────────
//  Types & Constants
// ─────────────────────────────────────────────────────────────

interface AttemptState {
    count: number;
    lockedUntil: number;
}

type LockoutState = Record<string, AttemptState>;

const SESSION_KEY = "vault_lockout_session";
const PERSISTENT_KEY = "vault_lockout_persistent";

/** lockout: 5s → 30s → 2m → 10m → 1h */
const LOCKOUT_DELAYS = [5_000, 30_000, 120_000, 600_000, 3_600_000] as const;
const MAX_ATTEMPTS_BEFORE_LOCK = 3;
const LOCK_TIMEOUT_MS = 5_000;

// ─────────────────────────────────────────────────────────────
//  Error
// ─────────────────────────────────────────────────────────────

export class VaultLockedError extends Error {
    constructor(public readonly retryAfterMs: number) {
        super(
            `Vault is locked. Try again in ${Math.ceil(retryAfterMs / 1000)}s`,
        );
        this.name = "VaultLockedError";
    }
}

// ─────────────────────────────────────────────────────────────
//  Storage (dual-write: session + persistent для стійкості)
// ─────────────────────────────────────────────────────────────

export async function getState(): Promise<LockoutState> {
    const [sessionResult, persistentResult] = await Promise.all([
        browser.storage.session.get(SESSION_KEY),
        browser.storage.local.get(PERSISTENT_KEY),
    ]);

    const session = (sessionResult[SESSION_KEY] as LockoutState) ?? {};
    const persistent = (persistentResult[PERSISTENT_KEY] as LockoutState) ?? {};

    // Merge: беремо максимум для захисту від ручного очищення session storage
    const merged: LockoutState = { ...persistent };
    for (const [email, s] of Object.entries(session)) {
        const p = merged[email];
        merged[email] = {
            count: Math.max(p?.count ?? 0, s.count),
            lockedUntil: Math.max(p?.lockedUntil ?? 0, s.lockedUntil),
        };
    }
    return merged;
}

async function setState(state: LockoutState): Promise<void> {
    await Promise.all([
        browser.storage.session.set({ [SESSION_KEY]: state }),
        browser.storage.local.set({ [PERSISTENT_KEY]: state }),
    ]);
}

// ─────────────────────────────────────────────────────────────
//  Concurrency Lock (захист від race conditions)
// ─────────────────────────────────────────────────────────────

let stateLock: Promise<void> = Promise.resolve();

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

// ─────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────

export async function checkUnlockAttempt(email: string): Promise<void> {
    return withLock(async () => {
        const state = await getState();
        const record = state[email];
        if (!record) return;

        const now = Date.now();

        // Автоматичне розблокування після закінчення lockout-періоду
        if (record.lockedUntil > 0 && record.lockedUntil <= now) {
            delete state[email];
            await setState(state);
            return;
        }

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

        if (record.lockedUntil > now) return;

        record.count++;

        if (record.count >= MAX_ATTEMPTS_BEFORE_LOCK) {
            const delayIndex = Math.min(
                record.count - MAX_ATTEMPTS_BEFORE_LOCK,
                LOCKOUT_DELAYS.length - 1,
            );
            record.lockedUntil = now + LOCKOUT_DELAYS[delayIndex]!;
        }

        state[email] = record;
        await setState(state);
    });
}

export async function resetAttempts(email: string): Promise<void> {
    return withLock(async () => {
        const state = await getState();
        if (email in state) {
            delete state[email];
            await setState(state);
        }
    });
}
