<script lang="ts">
import {
    onMount
} from 'svelte';
import {
    browser
} from 'wxt/browser';
import {
    messenger
} from '~/lib/messaging';
import {
    VaultError,
    type VaultErrorCode
} from '~/lib/types/error';

// ── Стан Vault ──────────────────────────────────────
let hasVault = $state < boolean | null > (null);
let isVaultUnlocked = $state(false);
let isLoading = $state(true);

// ── Створення Vault (перший запуск) ────────────────
let vaultPassword = $state('');
let vaultConfirmPassword = $state('');
let vaultError = $state('');
let isCreating = $state(false);

// ── Розблокування ──────────────────────────────────
let unlockPassword = $state('');
let unlockError = $state('');
let isUnlocking = $state(false);

// ── Генерація першого ключа ─────────────────────────
let genName = $state('');
let genEmail = $state('');
let genError = $state('');
let isGenerating = $state(false);
let _masterPassword: string | null = null;

// ────────────────────────────────────────────────────
//  Ініціалізація
// ────────────────────────────────────────────────────
onMount(async () => {
    try {
        isVaultUnlocked = await messenger.sendMessage('isVaultUnlocked', undefined);
        const keys = await messenger.sendMessage('listPrivateKeys', undefined);
        hasVault = keys.length > 0;
    } catch (err) {
        console.error('[popup] init error:', err);
        hasVault = false;
    } finally {
        isLoading = false;
    }
});

const openOptions = () => {
    if (browser.runtime.openOptionsPage) {
        browser.runtime.openOptionsPage();
    } else {
        window.open(browser.runtime.getURL('/options.html'));
    }
};

const submitCreateVault = async () => {
    vaultError = '';
    if (vaultPassword.length < 8) {
        vaultError = 'Пароль має містити щонайменше 8 символів';
        return;
    }
    if (vaultPassword !== vaultConfirmPassword) {
        vaultError = 'Паролі не співпадають';
        return;
    }

    isCreating = true;
    try {
        _masterPassword = vaultPassword;
        hasVault = true;
        isVaultUnlocked = true;
        vaultPassword = '';
        vaultConfirmPassword = '';
    } catch (err) {
        vaultError = extractErrorMessage(err, 'Не вдалося створити сховище');
    } finally {
        isCreating = false;
    }
};

const submitUnlock = async () => {
    unlockError = '';
    if (!unlockPassword) return;

    isUnlocking = true;
    try {
        const result = await messenger.sendMessage('unlockVault', unlockPassword);
        if (result.success) {
            isVaultUnlocked = true;
            _masterPassword = unlockPassword;
            unlockPassword = '';
        } else {
            unlockError = 'Невірний пароль';
        }
    } catch (err) {
        unlockError = extractErrorMessage(err, 'Невірний пароль або помилка розблокування');
    } finally {
        isUnlocking = false;
    }
};

const submitGenerate = async () => {
    genError = '';
    if (!genName.trim() || !genEmail.trim()) {
        genError = 'Заповніть усі поля';
        return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(genEmail)) {
        genError = 'Некоректна електронна адреса';
        return;
    }
    if (!_masterPassword) {
        genError = 'Сесія втрачена. Розблокуйте vault знову.';
        return;
    }
    isGenerating = true;
    try {
        await messenger.sendMessage('generateKeyPair', {
            email: genEmail.trim(),
            name: genName.trim(),
            masterPassword: _masterPassword,
        });
        hasVault = true;
        isVaultUnlocked = true;
        genName = '';
        genEmail = '';
        _masterPassword = null;
    } catch (err) {
        genError = extractErrorMessage(err, 'Помилка генерації');
    } finally {
        isGenerating = false;
    }
};

const handleLock = async () => {
    try {
        await messenger.sendMessage('lockVault', undefined);
    } finally {
        isVaultUnlocked = false;
        _masterPassword = null;
    }
};

function extractErrorMessage(err: unknown, fallback: string): string {
    if (err instanceof VaultError) {
        const map: Partial < Record < VaultErrorCode, string >> = {
            INVALID_PASSWORD: 'Невірний майстер-пароль',
            VAULT_LOCKED: 'Сховище заблоковане',
            RATE_LIMITED: `Забагато спроб. Спробуйте пізніше${
                    err.retryAfterMs ?
                    ` (${Math.ceil(err.retryAfterMs / 1000)} с)` : ''
                }`,
            KEY_ALREADY_EXISTS: 'Ключ для цієї пошти вже існує',
            CORRUPTED_DATA: 'Дані сховища пошкоджено',
        };
        return map[err.code] ?? err.message;
    }
    if (err instanceof Error) return err.message || fallback;
    return fallback;
}

const handleImageError = (e: Event) => {
    const target = e.currentTarget as HTMLImageElement;
    if (target) target.style.display = 'none';
};
</script>

<div class="container">
    <header>
        <div class="brand">
            <img src="/icon/logo-32.png" alt="Logo" class="logo" onerror={handleImageError} />
            <h1>MailShroud</h1>
        </div>
        <button class="icon-btn" onclick={openOptions} title="Налаштування">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round">
                <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
                <circle cx="12" cy="12" r="3" />
            </svg>
        </button>
    </header>

    <main>
        {#if isLoading}
        <div class="state-container">
            <div class="loader"></div>
            <p>Завантаження...</p>
        </div>

        {:else if !hasVault}
        <div class="form-container fade-in">
            <div class="icon-shield">
                <svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24"
                    fill="none" stroke="currentColor" stroke-width="1.5"
                    stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
            </div>
            <h2 class="text-center">Вітаємо в MailShroud!</h2>
            <p class="subtitle text-center">
                Створіть надійний пароль (мін. 8 символів). Він шифрує ваші ключі локально (AES-256-GCM).
            </p>
            <form onsubmit={(e) => { e.preventDefault(); submitCreateVault(); }}>
                <div class="input-group">
                    <label for="vault-password">Майстер-пароль</label>
                    <input id="vault-password" type="password"
                        bind:value={vaultPassword}
                        placeholder="Надійний пароль" required minlength="8" />
                </div>
                <div class="input-group">
                    <label for="vault-confirm">Підтвердіть пароль</label>
                    <input id="vault-confirm" type="password"
                        bind:value={vaultConfirmPassword}
                        placeholder="Повторіть пароль" required minlength="8" />
                </div>
                {#if vaultError}
                <p class="error-text mt-2">{vaultError}</p>
                {/if}
                <button type="submit" class="btn btn-primary mt-2" disabled={isCreating}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-svg"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>{isCreating ? 'Створення...' : 'Створити сховище'}</span>
                </button>
            </form>
        </div>

        {:else if !isVaultUnlocked}
        <div class="state-container fade-in">
            <div class="icon-lock">
                <svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24"
                    fill="none" stroke="currentColor" stroke-width="1.5"
                    stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
            </div>
            <div class="vault-title-wrapper">
                <h2>Сховище ключів</h2>
                <div class="status-dot locked" title="Заблоковано"></div>
            </div>
            <p>Введіть ваш пароль для розблокування.</p>
            <form onsubmit={(e) => { e.preventDefault(); submitUnlock(); }} style="width: 100%;">
                <div class="input-group">
                    <input type="password" bind:value={unlockPassword}
                        placeholder="Пароль від сховища" required minlength="8"
                        disabled={isUnlocking} />
                </div>
                {#if unlockError}
                <p class="error-text mt-2">{unlockError}</p>
                {/if}
                <button type="submit" class="btn btn-primary" disabled={isUnlocking}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-svg"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>
                    <span>{isUnlocking ? 'Розблокування...' : 'Розблокувати'}</span>
                </button>
            </form>
        </div>

        {:else if hasVault && isVaultUnlocked}
        {@const keysCheck = (async () => {
        const k = await messenger.sendMessage('listPrivateKeys', undefined);
        return k.length;
        })()}

        {#await keysCheck then count}
        {#if count === 0}
        <div class="form-container fade-in">
            <h2 class="text-center">Створення першого ключа</h2>
            <p class="subtitle text-center">
                Ваше сховище готове! Згенеруйте пару ключів для власного Gmail.
            </p>
            <form onsubmit={(e) => { e.preventDefault(); submitGenerate(); }}>
                <div class="input-group">
                    <label for="name">Ваше ім'я</label>
                    <input id="name" type="text" bind:value={genName}
                        placeholder="John Doe" required disabled={isGenerating} />
                </div>
                <div class="input-group">
                    <label for="email">Пошта Gmail</label>
                    <input id="email" type="email" bind:value={genEmail}
                        placeholder="your.email@gmail.com" required disabled={isGenerating} />
                </div>
                {#if genError}
                <p class="error-text mt-2">{genError}</p>
                {/if}
                <button type="submit" class="btn btn-primary mt-2" disabled={isGenerating}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-svg"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 1.5 1.5M15.5 7.5 14 6"/></svg>
                    <span>{isGenerating ? 'Генерація (ECC)...' : 'Згенерувати ключ'}</span>
                </button>
            </form>
        </div>
        {:else}
        <div class="state-container fade-in">
            <div class="icon-lock unlocked-theme">
                <svg xmlns="http://www.w3.org/2000/svg" width="42" height="42" viewBox="0 0 24 24"
                    fill="none" stroke="currentColor" stroke-width="1.5"
                    stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 9.9-1" />
                </svg>
            </div>
            <div class="vault-title-wrapper">
                <h2>Сховище ключів</h2>
                <div class="status-dot unlocked" title="Розблоковано"></div>
            </div>
            <p>Активних ключів: <strong>{count}</strong><br/>
                Шифрування Gmail активне</p>
            <button onclick={handleLock} class="btn btn-secondary mt-2">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-svg"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <span>Заблокувати сховище</span>
            </button>
            <button onclick={openOptions} class="btn btn-primary mt-2">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-svg"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
                <span>Керувати ключами</span>
            </button>
        </div>
        {/if}
        {/await}
        {/if}
    </main>
</div>

<style>
:global(body) {
    margin: 0;
    padding: 0;
    background-color: transparent;
}

.container {
    width: 340px;
    min-height: 400px;
    font-family: system-ui, -apple-system, sans-serif;
    background-color: #ffffff;
    color: #1f2937;
    display: flex;
    flex-direction: column;
    overflow-x: hidden;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 16px;
    background-color: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
}

.brand {
    display: flex;
    align-items: center;
    gap: 10px;
}

.logo {
    width: 24px;
    height: 24px;
    object-fit: contain;
}

header h1 {
    margin: 0;
    font-size: 1.125rem;
    font-weight: 600;
    color: #0f172a;
}

.icon-btn {
    background: transparent;
    border: none;
    color: #64748b;
    cursor: pointer;
    padding: 6px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
}

.icon-btn:hover {
    background-color: #e2e8f0;
    color: #0f172a;
}

main {
    padding: 20px;
    flex: 1;
    display: flex;
    flex-direction: column;
}

.state-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    justify-content: center;
    flex: 1;
}

.state-container p {
    font-size: 14px;
}

.form-container {
    display: flex;
    flex-direction: column;
    flex: 1;
    justify-content: center;
}

.text-center {
    text-align: center;
}

h2 {
    font-size: 1.25rem;
    margin: 0 0 10px 0;
    color: #0f172a;
}

.vault-title-wrapper h2 {
    margin: 0;
}

p {
    font-size: 0.875rem;
    color: #64748b;
    margin: 0 0 20px 0;
    line-height: 1.5;
}

.subtitle {
    margin-bottom: 16px;
}

.vault-title-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 10px;
}

.status-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    display: inline-block;
}

.status-dot.unlocked {
    background-color: #10b981;
    box-shadow: 0 0 6px rgba(16, 185, 129, 0.4);
}

.status-dot.locked {
    background-color: #ef4444;
    box-shadow: 0 0 6px rgba(239, 68, 68, 0.4);
}

.error-text {
    color: #ef4444;
    font-size: 0.8rem;
    margin: 4px 0 10px 0;
    text-align: left;
}

/* Збільшені та пропорційно вирівняні контейнери для іконок головного статусу розширення */
.icon-shield,
.icon-lock {
    margin-bottom: 20px;
    width: 80px;          /* Збільшено з 64px */
    height: 80px;         /* Збільшено з 64px */
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    align-self: center;
    flex-shrink: 0;
}

.icon-shield {
    color: #3b82f6;
    background: #eff6ff;
}

.icon-lock {
    color: #ef4444;
    background: #fef2f2;
}

.unlocked-theme {
    color: #10b981 !important;
    background: #ecfdf5 !important;
}

.input-group {
    margin-bottom: 14px;
    text-align: left;
    width: 100%;
}

label {
    display: block;
    font-size: 0.8rem;
    font-weight: 500;
    color: #475569;
    margin-bottom: 6px;
}

input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    box-sizing: border-box;
    font-size: 0.875rem;
    background-color: #f8fafc;
}

input:focus {
    outline: none;
    border-color: #3b82f6;
    background-color: #ffffff;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.btn {
    width: 100%;
    padding: 10px 16px;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.875rem;
    cursor: pointer;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    gap: 8px;
}

.btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.btn-icon-svg {
    display: inline-block;
    flex-shrink: 0;
}

.btn-primary {
    background-color: #3b82f6;
    color: white;
}

.btn-primary:hover:not(:disabled) {
    background-color: #2563eb;
}

.btn-secondary {
    background-color: #f1f5f9;
    color: #334155;
    border: 1px solid #cbd5e1;
}

.mt-2 {
    margin-top: 10px;
}

.loader {
    border: 3px solid #f3f3f3;
    border-top: 3px solid #3b82f6;
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin-bottom: 16px;
}

@keyframes spin {
    0% {
        transform: rotate(0deg);
    }

    100% {
        transform: rotate(360deg);
    }
}

.fade-in {
    animation: fadeIn 0.3s ease-in-out;
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(5px);
    }

    to {
        opacity: 1;
        transform: translateY(0);
    }
}
</style>