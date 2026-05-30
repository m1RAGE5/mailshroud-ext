<script lang="ts">
import {
    onMount
} from 'svelte';
import {
    messenger
} from '~/lib/messaging';
import {
    VaultError,
    type VaultErrorCode
} from '~/lib/types/error';
import type {
    KeyInfo
} from '~/lib/types/messages';

type ActiveTab = 'my-keys' | 'contacts';
let activeTab = $state < ActiveTab > ('my-keys');

// ── Реальні дані з background ──────────────────────
let myKeys = $state < KeyInfo[] > ([]);
let contacts = $state < KeyInfo[] > ([]);
let isVaultUnlocked = $state(false);
let isLoading = $state(true);

// ── Пошук ──────────────────────────────────────────
let contactSearchQuery = $state('');
let filteredContacts = $derived(
    contacts.filter(c =>
        c.email.toLowerCase().includes(contactSearchQuery.toLowerCase())
    )
);

// ── Модалки ────────────────────────────────────────
let isGenModalOpen = $state(false);
let isImportModalOpen = $state(false);
let isContactModalOpen = $state(false);
let isConfirmDeleteOpen = $state(false);
let deleteTarget = $state < {
    type: 'key' | 'contact';email: string
} | null > (null);

// ── Генерація ──────────────────────────────────────
let newKeyName = $state('');
let newKeyEmail = $state('');
let genError = $state('');
let isGenerating = $state(false);

// ── Імпорт приватного ключа ────────────────────────
// Увага: MailShroud приймає ТІЛЬКИ ключі БЕЗ passphrase
// (шифрування робиться AES-GCM vault-ом, а не OpenPGP passphrase)
let importKeyBlock = $state('');
let importEmail = $state('');
let importMasterPassword = $state('');
let importError = $state('');
let isImporting = $state(false);

// ── Додавання контакту (public key) ────────────────
let contactEmail = $state('');
let contactKeyBlock = $state('');
let contactError = $state('');
let isAddingContact = $state(false);

// ── Toast ──────────────────────────────────────────
let toastMessage = $state('');
let toastType = $state < 'success' | 'error' | 'info' > ('success');

function showToast(msg: string, type: 'success' | 'error' | 'info' = 'success') {
    toastMessage = msg;
    toastType = type;
    setTimeout(() => {
        toastMessage = '';
    }, 4000);
}

// ────────────────────────────────────────────────────
//  Завантажити все з background
// ────────────────────────────────────────────────────
async function refreshData() {
    try {
        isVaultUnlocked = await messenger.sendMessage('isVaultUnlocked', undefined);
        const [priv, pub] = await Promise.all([
            messenger.sendMessage('listPrivateKeys', undefined),
            messenger.sendMessage('listPublicKeys', undefined),
        ]);
        myKeys = priv;
        // Контакти = публічні ключі, що НЕ належать нам
        const ownEmails = new Set(priv.map(k => k.email.toLowerCase()));
        contacts = pub.filter(k => !ownEmails.has(k.email.toLowerCase()));
    } catch (err) {
        console.error('[options] refresh error:', err);
        showToast('Помилка завантаження даних', 'error');
    }
}

onMount(async () => {
    await refreshData();
    isLoading = false;
});

// ────────────────────────────────────────────────────
//  Утиліти
// ────────────────────────────────────────────────────
function formatFingerprint(fp: string): string {
    // v6 fingerprint = 64 hex chars → групуємо по 4
    return fp.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? fp;
}

function formatDate(ts: number): string {
    return new Date(ts).toISOString().split('T')[0];
}
async function copyToClipboard(text: string, msg = 'Скопійовано') {
    try {
        await navigator.clipboard.writeText(text);
        showToast(msg, 'success');
    } catch {
        showToast('Не вдалося скопіювати', 'error');
    }
}

function downloadAsFile(filename: string, text: string) {
    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
    a.download = filename;
    a.click();
}

function extractError(err: unknown, fallback: string): string {
    if (err instanceof VaultError) {
        const map: Partial < Record < VaultErrorCode, string >> = {
            INVALID_PASSWORD: 'Невірний майстер-пароль',
            VAULT_LOCKED: 'Сховище заблоковане. Розблокуйте через popup.',
            RATE_LIMITED: 'Забагато спроб. Зачекайте.',
            KEY_ALREADY_EXISTS: 'Ключ для цієї пошти вже існує',
            CORRUPTED_DATA: 'Дані пошкоджено',
            NO_MATCHING_KEY: 'Не знайдено відповідного ключа',
        };
        return map[err.code] ?? err.message;
    }
    return err instanceof Error ? err.message : fallback;
}

// ────────────────────────────────────────────────────
//  Генерація ключа
// ────────────────────────────────────────────────────
const handleGenerateKey = async () => {
    genError = '';

    if (!isVaultUnlocked) {
        genError = 'Сховище заблоковане. Розблокуйте його через popup.';
        return;
    }

    if (!newKeyName.trim() || !newKeyEmail.trim()) {
        genError = 'Заповніть усі поля';
        return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(newKeyEmail)) {
        genError = 'Некоректна email-адреса';
        return;
    }

    isGenerating = true;
    try {
        const result = await messenger.sendMessage('generateKeyPair', {
            email: newKeyEmail.trim(),
            name: newKeyName.trim(),
        });

        showToast(
            `Ключ згенеровано. Відбиток: ${result.privateKeyFingerprint.slice(0, 16)}…`,
            'success'
        );

        newKeyName = '';
        newKeyEmail = '';
        isGenModalOpen = false;
        await refreshData();
    } catch (err) {
        genError = extractError(err, 'Помилка генерації');
    } finally {
        isGenerating = false;
    }
};

// ────────────────────────────────────────────────────
//  Імпорт приватного ключа
//  (тут спрощено: реальний flow вимагає попереднього
//   розшифрування armored-key на стороні UI через OpenPGP.js,
//   шифрування його AES-GCM з master-password і відправки у background.
//   Для MVP показуємо тільки валідацію формату)
// ────────────────────────────────────────────────────
const handleImportKey = async () => {
    importError = '';
    if (!importKeyBlock.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
        importError = 'Очікується PGP PRIVATE KEY BLOCK';
        return;
    }
    if (!importEmail.trim() || !importMasterPassword) {
        importError = 'Вкажіть email та майстер-пароль';
        return;
    }
    isImporting = true;
    try {
        // ⚠️ Для повноцінного імпорту потрібен окремий endpoint,
        // який приймає armored private key без passphrase,
        // шифрує його AES-GCM з masterPassword і кладе в БД.
        // Наразі використовуємо storePrivateKey з підготовленими даними.
        // TODO: реалізувати handleImportArmoredPrivateKey у background.
        importError = 'Імпорт приватних ключів ще не реалізовано. Використовуйте генерацію.';
    } catch (err) {
        importError = extractError(err, 'Помилка імпорту');
    } finally {
        isImporting = false;
    }
};

// ── Безпечний експорт приватного ключа ────────────────────────
let isExportPrivModalOpen = $state(false);
let exportPrivEmail = $state('');
let exportPrivPassword = $state('');
let exportPrivError = $state('');
let isExportingPriv = $state(false);

const openExportPrivModal = (email: string) => {
    exportPrivEmail = email;
    exportPrivPassword = '';
    exportPrivError = '';
    isExportPrivModalOpen = true;
};

const handleExportPrivateKeySubmit = async () => {
    exportPrivError = '';
    if (!exportPrivPassword) {
        exportPrivError = 'Введіть майстер-пароль для підтвердження';
        return;
    }

    isExportingPriv = true;
    try {
        // Відправляємо запит у background з паролем
        const armoredPrivateKey = await messenger.sendMessage('exportPrivateKey', {
            email: exportPrivEmail,
            masterPassword: exportPrivPassword
        });

        // Скачуємо файл на ПК
        downloadAsFile(`private_key_${exportPrivEmail}.asc`, armoredPrivateKey);
        showToast('Приватний ключ успішно експортовано! Зберігайте його в таємниці.', 'success');
        isExportPrivModalOpen = false;
    } catch (err) {
        exportPrivError = extractError(err, 'Помилка експорту ключа');
    } finally {
        isExportingPriv = false;
    }
};

// ────────────────────────────────────────────────────
//  Додавання контакту (public key)
// ────────────────────────────────────────────────────
const handleAddContact = async () => {
    contactError = '';
    if (!contactEmail.trim() || !contactKeyBlock.trim()) {
        contactError = 'Заповніть email та PGP PUBLIC KEY BLOCK';
        return;
    }
    if (!contactKeyBlock.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        contactError = 'Має бути PGP PUBLIC KEY BLOCK';
        return;
    }
    isAddingContact = true;
    try {
        await messenger.sendMessage('storePublicKey', {
            email: contactEmail.trim(),
            armoredKey: contactKeyBlock.trim(),
            source: 'manual',
            verified: false,
        });
        showToast(`Контакт ${contactEmail} додано`, 'success');
        contactEmail = '';
        contactKeyBlock = '';
        isContactModalOpen = false;
        await refreshData();
    } catch (err) {
        contactError = extractError(err, 'Не вдалося додати контакт');
    } finally {
        isAddingContact = false;
    }
};

// ────────────────────────────────────────────────────
//  Видалення
// ────────────────────────────────────────────────────
const startDelete = (type: 'key' | 'contact', email: string) => {
    deleteTarget = {
        type,
        email
    };
    isConfirmDeleteOpen = true;
};
const confirmDelete = async () => {
    if (!deleteTarget) return;
    try {
        if (deleteTarget.type === 'key') {
            await messenger.sendMessage('deletePrivateKey', deleteTarget.email);
            showToast('Приватний ключ видалено', 'info');
        } else {
            await messenger.sendMessage('deletePublicKey', deleteTarget.email);
            showToast('Контакт видалено', 'info');
        }
        await refreshData();
    } catch (err) {
        showToast(extractError(err, 'Помилка видалення'), 'error');
    } finally {
        isConfirmDeleteOpen = false;
        deleteTarget = null;
    }
};

// ────────────────────────────────────────────────────
//  Експорт public key
// ────────────────────────────────────────────────────
const exportPublicKey = async (email: string) => {
    try {
        const armored = await messenger.sendMessage('getPublicKey', email);
        if (armored) {
            downloadAsFile(`public_key_${email}.asc`, armored);
            showToast('Публічний ключ експортовано', 'success');
        }
    } catch (err) {
        showToast(extractError(err, 'Помилка експорту'), 'error');
    }
};

// ────────────────────────────────────────────────────
//  Копіювання public key
// ────────────────────────────────────────────────────
const copyPublicKey = async (email: string) => {
    try {
        const armored = await messenger.sendMessage('getPublicKey', email);
        if (armored) {
            await copyToClipboard(armored, 'Публічний ключ скопійовано');
        } else {
            showToast('Публічний ключ не знайдено', 'error');
        }
    } catch (err) {
        showToast(extractError(err, 'Помилка отримання ключа'), 'error');
    }
};
</script>

<div class="app-container">
    <header class="app-header">
        <div class="header-brand">
            <img src="/icon/logo-48.png" alt="Logo" class="logo-img" />
            <div class="header-titles">
                <h1>MailShroud</h1>
                <p>Панель керування PGP-шифруванням</p>
            </div>
        </div>
        <div class="header-version">
            {#if isVaultUnlocked}
            <span class="status-badge unlocked">● Vault відкритий</span>
            {:else}
            <span class="status-badge locked">● Vault закритий</span>
            {/if}
        </div>
    </header>

    {#if toastMessage}
    <div class="toast toast-{toastType}">
        <span class="toast-icon">
            {#if toastType === 'success'} ✓ {:else if toastType === 'error'} ⚠ {:else} ℹ {/if}
        </span>
        <span class="toast-text">{toastMessage}</span>
    </div>
    {/if}

    <main class="app-layout">
        <aside class="sidebar">
            <button type="button" class="nav-item {activeTab === 'my-keys' ? 'active' : ''}"
                onclick={() => activeTab = 'my-keys'}>
                <div class="nav-label"><span class="nav-icon">🔑</span> Власні ключі</div>
                <span class="badge">{myKeys.length}</span>
            </button>
            <button type="button" class="nav-item {activeTab === 'contacts' ? 'active' : ''}"
                onclick={() => activeTab = 'contacts'}>
                <div class="nav-label"><span class="nav-icon">👥</span> Контакти</div>
                <span class="badge">{contacts.length}</span>
            </button>
            <div class="info-panel">
                <h4>Безпека</h4>
                <p>Приватні ключі шифруються AES-256-GCM з PBKDF2 (600 000 ітерацій) і ніколи не залишають background.</p>
                <p>Використовується OpenPGP v6 (Curve25519 + AEAD-GCM).</p>
            </div>
        </aside>

        <section class="main-panel">
            {#if isLoading}
            <div class="empty-state">
                <div class="loader"></div>
                <p>Завантаження...</p>
            </div>

            {:else if !isVaultUnlocked}
            <div class="empty-state">
                <div class="empty-icon">🔒</div>
                <h3>Vault заблоковано</h3>
                <p>Розблокуйте сховище через popup-іконку розширення, щоб керувати ключами.</p>
            </div>

            {:else if activeTab === 'my-keys'}
            <div class="panel-header">
                <div class="panel-title">
                    <h2>Ваші PGP-ключі</h2>
                    <p>Приватні ключі зберігаються зашифrovano. Відбиток — це публічний ідентифікатор.</p>
                </div>
                <div class="panel-actions">
                    <button type="button" onclick={() => isGenModalOpen = true} class="btn btn-primary">
                        + Згенерувати ключ
                    </button>
                </div>
            </div>

            {#if myKeys.length === 0}
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <h3>У вас немає ключів</h3>
                <p>Згенеруйте першу PGP-пару для вашої Gmail-адреси.</p>
            </div>
            {:else}
            <div class="list-container">
                {#each myKeys as key (key.fingerprint)}
                <div class="card">
                    <div class="card-content">
                        <div class="card-info">
                            <div class="card-title-row">
                                <h3>{key.email}</h3>
                                <span class="tag tag-blue">v6</span>
                                <span class="tag tag-gray">{formatDate(key.createdAt)}</span>
                            </div>
                            <p class="card-fingerprint" title="Повний відбиток">
                                🔐 {formatFingerprint(key.fingerprint)}
                            </p>
                        </div>
                        <div class="card-actions">
                            <button type="button" class="btn-icon"
                                onclick={() => copyPublicKey(key.email)}>
                                Копіювати public
                            </button>
                            <button type="button" class="btn-icon"
                                onclick={() => exportPublicKey(key.email)}>
                                Експорт public
                            </button>
                            <button type="button" class="btn-icon" style="border-color: #fbcfe8; color: #db2777;" onclick={() => openExportPrivModal(key.email)}>
                                🔑 Експорт private
                            </button>
                            <button type="button" class="btn-delete"
                                onclick={() => startDelete('key', key.email)}>
                                Видалити
                            </button>
                        </div>
                    </div>
                </div>
                {/each}
            </div>
            {/if}

            {:else}
            <!-- КОНТАКТИ -->
            <div class="panel-header">
                <div class="panel-title">
                    <h2>Публічні ключі контактів</h2>
                    <p>Додавайте public key ваших кореспондентів, щоб шифрувати листи до них.</p>
                </div>
                <div class="panel-actions">
                    <button type="button" onclick={() => isContactModalOpen = true} class="btn btn-primary">
                        + Додати контакт
                    </button>
                </div>
            </div>

            <div class="search-bar">
                <span class="search-icon">🔍</span>
                <input type="text" bind:value={contactSearchQuery}
                    placeholder="Пошук за email..." />
                {#if contactSearchQuery}
                <button type="button" class="clear-search"
                    onclick={() => contactSearchQuery = ''}>✕</button>
                {/if}
            </div>

            {#if filteredContacts.length === 0}
            <div class="empty-state">
                <div class="empty-icon">📁</div>
                <h3>{contactSearchQuery ? 'Нічого не знайдено' : 'Контактів немає'}</h3>
                <p>Додайте перший публічний ключ, щоб шифрувати листи.</p>
            </div>
            {:else}
            <div class="list-container">
                {#each filteredContacts as c (c.fingerprint)}
                <div class="card">
                    <div class="card-content">
                        <div class="card-info">
                            <div class="card-title-row">
                                <h3>{c.email}</h3>
                                {#if c.verified}<span class="tag tag-green">✓ verified</span>{/if}
                                <span class="tag tag-gray">{formatDate(c.createdAt)}</span>
                            </div>
                            <p class="card-fingerprint">
                                🔐 {formatFingerprint(c.fingerprint)}
                            </p>
                        </div>
                        <div class="card-actions">
                            <button type="button" class="btn-icon"
                                onclick={() => copyToClipboard(c.fingerprint, 'Відбиток скопійовано')}>
                                Копіювати FP
                            </button>
                            <button type="button" class="btn-delete"
                                onclick={() => startDelete('contact', c.email)}>
                                Видалити
                            </button>
                        </div>
                    </div>
                </div>
                {/each}
            </div>
            {/if}
            {/if}
        </section>
    </main>
</div>

<!-- ═══ МОДАЛЬНІ ВІКНА ═══ -->
{#if isGenModalOpen || isImportModalOpen || isContactModalOpen || isConfirmDeleteOpen || isExportPrivModalOpen}
<div class="modal-overlay" onclick={() => {
    isGenModalOpen = false;
    isImportModalOpen = false;
    isContactModalOpen = false;
    isConfirmDeleteOpen = false;
    isExportPrivModalOpen = false;
    }} role="presentation"></div>
{/if}

{#if isGenModalOpen}
<div class="modal">
    <h2>Генерація PGP-ключа</h2>
    <p class="modal-desc">
        Буде створено v6-ключ (Curve25519) та зашифровано майстер-паролем вашого сховища.
    </p>
    <form onsubmit={(e) => { e.preventDefault(); handleGenerateKey(); }}>
        <div class="form-group">
            <label for="nk-name">Ім'я</label>
            <input id="nk-name" type="text" bind:value={newKeyName}
                placeholder="John Doe" required />
        </div>
        <div class="form-group">
            <label for="nk-email">Email</label>
            <input id="nk-email" type="email" bind:value={newKeyEmail}
                placeholder="you@gmail.com" required />
        </div>

        <!-- ❌ ПОЛЕ МАЙСТЕР-ПАРОЛЯ ПРИБРАНО -->

        {#if genError}
        <p class="error-msg">{genError}</p>
        {/if}
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary"
                onclick={() => isGenModalOpen = false}>
                Скасувати
            </button>
            <button type="submit" class="btn btn-primary" disabled={isGenerating}>
                {isGenerating ? 'Генерація...' : 'Згенерувати'}
            </button>
        </div>
    </form>
</div>
{/if}

{#if isContactModalOpen}
<div class="modal modal-large">
    <h2>Додати публічний ключ контакта</h2>
    <form onsubmit={(e) => { e.preventDefault(); handleAddContact(); }}>
        <div class="form-group">
            <label for="c-email">Email контакта</label>
            <input id="c-email" type="email" bind:value={contactEmail} placeholder="friend@gmail.com" required />
        </div>
        <div class="form-group">
            <label for="c-key">PGP PUBLIC KEY BLOCK</label>
            <textarea id="c-key" bind:value={contactKeyBlock}
                placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----" rows="10" required></textarea>
        </div>
        {#if contactError} <p class="error-msg">{contactError}</p> {/if}
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick={() => isContactModalOpen = false}>Скасувати</button>
            <button type="submit" class="btn btn-primary" disabled={isAddingContact}>
                {isAddingContact ? 'Збереження...' : 'Зберегти контакт'}
            </button>
        </div>
    </form>
</div>
{/if}

{#if isConfirmDeleteOpen && deleteTarget}
<div class="modal modal-small">
    <h2>Підтвердження</h2>
    <p class="modal-desc">
        Видалити {deleteTarget.type === 'key' ? 'приватний ключ' : 'контакт'}
        <strong>{deleteTarget.email}</strong>? Цю дію не можна скасувати.
    </p>
    <div class="modal-footer">
        <button type="button" class="btn btn-secondary" onclick={() => isConfirmDeleteOpen = false}>Скасувати</button>
        <button type="button" class="btn btn-danger" onclick={confirmDelete}>Видалити</button>
    </div>
</div>
{/if}

{#if isExportPrivModalOpen}
<div class="modal modal-small">
    <h2>Безпечний експорт ключа</h2>
    <p class="modal-desc" style="color: #ef4444; font-weight: 500;">
        Увага! Ви експортуєте ПРИВАТНИЙ КЛЮЧ для <strong>{exportPrivEmail}</strong>. Нікому не передавайте цей файл!
    </p>
    <form onsubmit={(e) => { e.preventDefault(); handleExportPrivateKeySubmit(); }}>
        <div class="form-group">
            <label for="xp-password">Підтвердіть ваш майстер-пароль</label>
            <input id="xp-password" type="password" bind:value={exportPrivPassword} placeholder="Введіть майстер-пароль сховища" required />
        </div>

        {#if exportPrivError}
        <p class="error-msg">{exportPrivError}</p>
        {/if}

        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick={() => isExportPrivModalOpen = false}>
                Скасувати
            </button>
            <button type="submit" class="btn btn-danger" style="background: #db2777;" disabled={isExportingPriv}>
                {isExportingPriv ? 'Дешифрування...' : 'Підтвердити та завантажити'}
            </button>
        </div>
    </form>
</div>
{/if}

<style>
/* ... ваші стилі без змін + нові ... */
:global(html),
:global(body) {
    margin: 0;
    padding: 0;
    background-color: #f1f5f9;
    font-family: system-ui, sans-serif;
    color: #1e293b;
}

.app-container {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

.app-header {
    background: #fff;
    border-bottom: 1px solid #e2e8f0;
    padding: 16px 40px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 10;
}

.header-brand {
    display: flex;
    align-items: center;
    gap: 16px;
}

.logo-img {
    width: 48px;
    height: 48px;
}

.header-titles h1 {
    margin: 0;
    font-size: 24px;
}

.header-titles p {
    margin: 0;
    font-size: 14px;
    color: #64748b;
}

.status-badge {
    font-size: 13px;
    font-weight: 600;
    padding: 6px 12px;
    border-radius: 20px;
}

.status-badge.unlocked {
    background: #ecfdf5;
    color: #059669;
}

.status-badge.locked {
    background: #fef2f2;
    color: #dc2626;
}

.app-layout {
    display: flex;
    flex: 1;
    max-width: 1300px;
    margin: 0 auto;
    padding: 32px 40px;
    gap: 40px;
    width: 100%;
    box-sizing: border-box;
}

.sidebar {
    width: 280px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.nav-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    background: transparent;
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-weight: 500;
    color: #475569;
    cursor: pointer;
    text-align: left;
}

.nav-item:hover {
    background: #e2e8f0;
}

.nav-item.active {
    background: #2563eb;
    color: #fff;
}

.nav-label {
    display: flex;
    align-items: center;
    gap: 12px;
}

.badge {
    background: #cbd5e1;
    color: #334155;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
}

.nav-item.active .badge {
    background: rgba(255, 255, 255, 0.2);
    color: #fff;
}

.info-panel {
    margin-top: 24px;
    background: #e2e8f0;
    padding: 20px;
    border-radius: 16px;
    font-size: 13px;
    color: #475569;
}

.info-panel h4 {
    margin: 0 0 12px;
    text-transform: uppercase;
    font-size: 12px;
}

.info-panel p {
    margin: 0 0 8px;
}

.main-panel {
    flex: 1;
    background: #fff;
    border-radius: 24px;
    padding: 40px;
    border: 1px solid #e2e8f0;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid #f1f5f9;
    padding-bottom: 24px;
    margin-bottom: 24px;
}

.panel-title h2 {
    margin: 0;
    font-size: 28px;
}

.panel-title p {
    margin: 8px 0 0;
    font-size: 16px;
    color: #64748b;
}

.panel-actions {
    display: flex;
    gap: 12px;
}

.btn {
    padding: 12px 24px;
    font-size: 16px;
    font-weight: 600;
    border-radius: 12px;
    cursor: pointer;
    border: none;
}

.btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.btn-primary {
    background: #2563eb;
    color: #fff;
}

.btn-primary:hover:not(:disabled) {
    background: #1d4ed8;
}

.btn-secondary {
    background: #f1f5f9;
    color: #334155;
    border: 1px solid #cbd5e1;
}

.btn-danger {
    background: #ef4444;
    color: #fff;
}

.search-bar {
    position: relative;
    margin-bottom: 24px;
}

.search-icon {
    position: absolute;
    left: 16px;
    top: 50%;
    transform: translateY(-50%);
    color: #94a3b8;
}

.search-bar input {
    width: 100%;
    padding: 16px 16px 16px 48px;
    font-size: 16px;
    border-radius: 16px;
    border: 1px solid #cbd5e1;
    background: #f8fafc;
    box-sizing: border-box;
}

.clear-search {
    position: absolute;
    right: 16px;
    top: 50%;
    transform: translateY(-50%);
    background: #e2e8f0;
    border: none;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    cursor: pointer;
}

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #64748b;
}

.empty-icon {
    font-size: 64px;
    margin-bottom: 20px;
    opacity: 0.5;
}

.empty-state h3 {
    color: #0f172a;
    font-size: 22px;
    margin: 0 0 10px;
}

.list-container {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.card {
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 24px;
    background: #fff;
}

.card-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
}

.card-title-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
    flex-wrap: wrap;
}

.card-title-row h3 {
    margin: 0;
    font-size: 20px;
}

.tag {
    font-size: 13px;
    padding: 4px 10px;
    border-radius: 8px;
    font-weight: 600;
    font-family: monospace;
}

.tag-blue {
    background: #eff6ff;
    color: #2563eb;
}

.tag-green {
    background: #ecfdf5;
    color: #059669;
}

.tag-gray {
    background: #f1f5f9;
    color: #475569;
}

.card-fingerprint {
    margin: 0;
    font-size: 13px;
    color: #94a3b8;
    font-family: monospace;
    user-select: all;
    word-break: break-all;
}

.card-actions {
    display: flex;
    gap: 12px;
}

.btn-icon {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    padding: 10px 16px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 600;
    color: #475569;
    cursor: pointer;
}

.btn-icon:hover {
    background: #eff6ff;
    border-color: #bfdbfe;
    color: #2563eb;
}

.btn-delete {
    background: #fef2f2;
    border: 1px solid #fee2e2;
    padding: 10px 16px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 600;
    color: #ef4444;
    cursor: pointer;
}

.btn-delete:hover {
    background: #fee2e2;
}

.modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(4px);
    z-index: 50;
}

.modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: #fff;
    padding: 40px;
    border-radius: 24px;
    width: 100%;
    max-width: 500px;
    box-sizing: border-box;
    z-index: 51;
}

.modal-large {
    max-width: 700px;
}

.modal-small {
    max-width: 400px;
}

.modal h2 {
    margin: 0 0 10px;
    font-size: 26px;
}

.modal-desc {
    margin: 0 0 24px;
    font-size: 16px;
    color: #64748b;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 20px;
}

.form-group label {
    font-size: 15px;
    font-weight: 600;
    color: #334155;
}

.form-group input,
.form-group textarea {
    padding: 14px 16px;
    font-size: 16px;
    border: 1px solid #cbd5e1;
    border-radius: 12px;
    background: #f8fafc;
    font-family: inherit;
}

.form-group textarea {
    resize: vertical;
    font-family: monospace;
    font-size: 14px;
}

.modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 16px;
    margin-top: 32px;
    padding-top: 24px;
    border-top: 1px solid #e2e8f0;
}

.error-msg {
    color: #ef4444;
    font-size: 14px;
    font-weight: 500;
    margin: 0 0 20px;
}

.toast {
    position: fixed;
    bottom: 30px;
    right: 30px;
    padding: 16px 24px;
    background: #1e293b;
    color: #fff;
    border-radius: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    z-index: 100;
}

.toast-success {
    border-left: 6px solid #10b981;
}

.toast-error {
    border-left: 6px solid #ef4444;
}

.toast-info {
    border-left: 6px solid #3b82f6;
}

.loader {
    border: 3px solid #f3f3f3;
    border-top: 3px solid #3b82f6;
    border-radius: 50%;
    width: 30px;
    height: 30px;
    animation: spin 1s linear infinite;
    margin: 0 auto 16px;
}

@keyframes spin {
    to {
        transform: rotate(360deg);
    }
}
</style>
