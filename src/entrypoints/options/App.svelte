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

// ── Керування замилюванням відбитків (Svelte 5 state) ──
let revealedFingerprints = $state(new Set < string > ());
function revealFingerprint(fp: string) {
    if (!revealedFingerprints.has(fp)) {
        revealedFingerprints.add(fp);
        revealedFingerprints = new Set(revealedFingerprints);
    }
}

function hideFingerprint(fp: string) {
    if (revealedFingerprints.has(fp)) {
        revealedFingerprints.delete(fp);
        revealedFingerprints = new Set(revealedFingerprints);
    }
}

function showToast(msg: string, type: 'success' | 'error' | 'info' = 'success') {
    toastMessage = msg;
    toastType = type;
    setTimeout(() => {
        toastMessage = '';
    }, 4000);
}

// ── Завантажити все з background ────────────────────
async function refreshData() {
    try {
        isVaultUnlocked = await messenger.sendMessage('isVaultUnlocked', undefined);
        const [priv, pub] = await Promise.all([
            messenger.sendMessage('listPrivateKeys', undefined),
            messenger.sendMessage('listPublicKeys', undefined),
        ]);
        myKeys = priv;
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

// ── Утиліти ─────────────────────────────────────────
function formatFingerprint(fp: string): string {
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
            INVALID_PASSWORD: 'Невірний пароль',
            VAULT_LOCKED: 'Сховище заблоковане. Розблокуйте через popup.',
            RATE_LIMITED: 'Забагато спроб. Зачекайте.',
            KEY_ALREADY_EXISTS: 'Ключ для цієї пошти вже існує',
            CORRUPTED_DATA: 'Дані пошкоджено',
            NO_MATCHING_KEY: 'Не знадено відповідного ключа',
        };
        return map[err.code] ?? err.message;
    }
    return err instanceof Error ? err.message : fallback;
}

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

const handleImportKey = async () => {
    importError = '';
    if (!importKeyBlock.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
        importError = 'Очікується PGP PRIVATE KEY BLOCK';
        return;
    }
    if (!importEmail.trim() || !importMasterPassword) {
        importError = 'Вкажіть email та пароль';
        return;
    }
    isImporting = true;
    try {
        importError = 'Імпорт приватних ключів ще не реалізовано. Використовуйте генерацію.';
    } catch (err) {
        importError = extractError(err, 'Помилка імпорту');
    } finally {
        isImporting = false;
    }
};

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
        exportPrivError = 'Введіть пароль сховища для підтвердження';
        return;
    }

    isExportingPriv = true;
    try {
        const armoredPrivateKey = await messenger.sendMessage('exportPrivateKey', {
            email: exportPrivEmail,
            masterPassword: exportPrivPassword
        });
        downloadAsFile(`private_key_${exportPrivEmail}.asc`, armoredPrivateKey);
        showToast('Приватний ключ успішно експортовано! Зберігайте його в таємниці.', 'success');
        isExportPrivModalOpen = false;
    } catch (err) {
        exportPrivError = extractError(err, 'Помилка експорту ключа');
    } finally {
        isExportingPriv = false;
    }
};

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

const exportPublicKey = async (email: string) => {
    try {
        const armored = await messenger.sendMessage('getPublicKey', email);
        if (armored) {
            downloadAsFile(`public_key_${email}.asc`, armored);
            showToast('Відкритий ключ експортовано', 'success');
        }
    } catch (err) {
        showToast(extractError(err, 'Помилка експорту'), 'error');
    }
};

const copyPublicKey = async (email: string) => {
    try {
        const armored = await messenger.sendMessage('getPublicKey', email);
        if (armored) {
            await copyToClipboard(armored, 'Відкритий ключ скопійовано');
        } else {
            showToast('Відкритий ключ не знайдено', 'error');
        }
    } catch (err) {
        showToast(extractError(err, 'Помилка отримання ключа'), 'error');
    }
};
</script>

<div class="app-container">
    <div class="page-wrapper">
    {#if toastMessage}
    <div class="toast toast-{toastType}">
        <span class="toast-icon">
            {#if toastType === 'success'}
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            {:else if toastType === 'error'}
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {:else}
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            {/if}
        </span>
        <span class="toast-text">{toastMessage}</span>
    </div>
    {/if}

    <div class="settings-box">
        <header class="box-header">
            <div class="header-brand">
                <img src="/icon/logo-48.png" alt="Logo" class="logo-img" />
                <div class="header-titles">
                    <h1>MailShroud</h1>
                    <p>Керування ключами шифрування Gmail</p>
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

        <div class="box-body">
            <aside class="sidebar">
                <button type="button" class="nav-item {activeTab === 'my-keys' ? 'active' : ''}"
                    onclick={() => activeTab = 'my-keys'}>
                    <div class="nav-label">
                        <span class="nav-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 1.5 1.5M15.5 7.5 14 6"/></svg>
                        </span> 
                        Власні ключі
                    </div>
                    <span class="badge">{myKeys.length}</span>
                </button>
             
                <button type="button" class="nav-item {activeTab === 'contacts' ? 'active' : ''}"
                    onclick={() => activeTab = 'contacts'}>
                    <div class="nav-label">
                        <span class="nav-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                        </span> 
                        Контакти
                    </div>
                    <span class="badge">{contacts.length}</span>
                </button>
              
                <div class="info-panel">
                    <h4>Безпека</h4>
                    <p>Приватні ключі шифруються AES-256-GCM з PBKDF2 (600 000 ітерацій).</p>
                    <p>Використовується OpenPGP v6 (Curve25519 + AEAD-GCM).</p>
                    <p>Відбиток – послідовність байтів, яка використовується для ідентифікації відкритого ключа.</p>
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
                    <div class="empty-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </div>
                    <h3>Сховище заблоковано!</h3>
                    <p>Розблокуйте його у спливаючому вікні розширення</p>
                </div>

                {:else if activeTab === 'my-keys'}
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>Власні ключі</h2>
                        <p>Додавайте власні ключі та діліться відкритими. Закриті (private) ключі зберігаються зашифровано.</p>
                    </div>
                    <div class="panel-actions">
                        <button type="button" onclick={() => isGenModalOpen = true} class="btn btn-primary">
                            + Згенерувати ключ
                        </button>
                    </div>
                </div>

                {#if myKeys.length === 0}
                <div class="empty-state">
                    <div class="empty-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </div>
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
                                <p class="card-fingerprint {revealedFingerprints.has(key.fingerprint) ? '' : 'blurred'}"
                                title={revealedFingerprints.has(key.fingerprint) ? "Повний відбиток" : "Натисніть, щоб показати відбиток"}
                                onclick={() => revealFingerprint(key.fingerprint)}
                                onmouseleave={() => hideFingerprint(key.fingerprint)}
                                role="presentation">
                                {formatFingerprint(key.fingerprint)}
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
                                    Експорт private
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
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>Ключі контактів</h2>
                        <p>Додавайте відкриті (public) ключі людей з якими ви контактуєте, щоб шифрувати листи для них.</p>
                    </div>
                    <div class="panel-actions">
                        <button type="button" onclick={() => isContactModalOpen = true} class="btn btn-primary">
                            + Додати контакт
                        </button>
                    </div>
                </div>

                <div class="search-bar">
                    <span class="search-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    </span>
                    <input type="text" bind:value={contactSearchQuery}
                        placeholder="Пошук за email..." />
                    {#if contactSearchQuery}
                    <button type="button" class="clear-search"
                        onclick={() => contactSearchQuery = ''}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    </button>
                    {/if}
                </div>

                {#if filteredContacts.length === 0}
                <div class="empty-state">
                    <div class="empty-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/></svg>
                    </div>
                    <h3>{contactSearchQuery ? 'Нічого не знайдено' : 'Контактів немає'}</h3>
                    <p>Додайте перший відкритий ключ, щоб шифрувати листи.</p>
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
                                <p class="card-fingerprint {revealedFingerprints.has(c.fingerprint) ? '' : 'blurred'}"
                                title={revealedFingerprints.has(c.fingerprint) ? "Відбиток" : "Натисніть, щоб показати відбиток"}
                                onclick={() => revealFingerprint(c.fingerprint)}
                                onmouseleave={() => hideFingerprint(c.fingerprint)}
                                role="presentation">
                                {formatFingerprint(c.fingerprint)}
                            </p>
                            </div>
                            <div class="card-actions">
                                <button type="button" class="btn-icon"
                                    onclick={() => copyPublicKey(c.email)}>
                                    Копіювати public
                                </button>
                                <button type="button" class="btn-icon"
                                    onclick={() => exportPublicKey(c.email)}>
                                    Експорт public
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
        </div>
    </div>
</div>
</div>

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
        Буде створено v6-ключ (Curve25519) та зашифровано паролем вашого сховища.
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
    <h2>Додати відкритий ключ контакта</h2>
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
    <h2>Експорт закритого ключа</h2>
    <p class="modal-desc" style="color: #ef4444; font-weight: 500;">
        Увага! Ви експортуєте ЗАКРИТИЙ КЛЮЧ <strong>{exportPrivEmail}</strong>. Нікому не передавайте цей файл!
    </p>
    <form onsubmit={(e) => { e.preventDefault(); handleExportPrivateKeySubmit(); }}>
        <div class="form-group">
            <label for="xp-password">Підтвердіть пароль</label>
            <input id="xp-password" type="password" bind:value={exportPrivPassword} placeholder="Пароль сховища" required />
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
:global(html),
:global(body) {
    margin: 0;
    padding: 0;
    background-color: #e2e8f0;
    font-family: system-ui, sans-serif;
    color: #1e293b;
    height: 100vh;
}

.page-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    padding: 40px;
    box-sizing: border-box;
}

.settings-box {
    background: #fff;
    width: 100%;
    max-width: 1100px;
    height: 85vh;
    min-height: 600px;
    border-radius: 24px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border: 1px solid #cbd5e1;
}

.box-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 24px 40px;
    border-bottom: 1px solid #e2e8f0;
    background: #fff;
    z-index: 10;
}

.box-body {
    display: flex;
    flex: 1;
    overflow: hidden;
}

.header-brand {
    display: flex;
    align-items: center;
    gap: 16px;
}

.logo-img { width: 48px; height: 48px; }
.header-titles h1 { margin: 0; font-size: 24px; }
.header-titles p { margin: 0; font-size: 14px; color: #64748b; }

.status-badge {
    font-size: 16px;
    font-weight: 600;
    padding: 6px 12px;
    border-radius: 20px;
}
.status-badge.unlocked { background: #ecfdf5; color: #059669; }
.status-badge.locked { background: #fef2f2; color: #dc2626; }

.sidebar {
    width: 280px;
    background: #f8fafc;
    border-right: 1px solid #e2e8f0;
    padding: 32px 24px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    overflow-y: auto;
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

.nav-item:hover { background: #e2e8f0; }
.nav-item.active { background: #2563eb; color: #fff; }

.nav-label {
    display: flex;
    align-items: center;
    gap: 12px;
}

.nav-icon {
    display: flex;
    align-items: center;
    justify-content: center;
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
    font-size: 14px;
    color: #475569;
}
.info-panel h4 { margin: 0 0 12px; text-transform: uppercase; font-size: 14px; }
.info-panel p { margin: 0 0 8px; }

.main-panel {
    flex: 1;
    background: #fff;
    padding: 40px;
    overflow-y: auto;
}

.panel-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid #f1f5f9;
    padding-bottom: 24px;
    margin-bottom: 24px;
}

.panel-title {
    margin-right: 32px;
}

.panel-header h2 {
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

.panel-actions .btn {
    min-width: 220px;
    text-align: center;
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
    display: flex;
    align-items: center;
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
    display: flex;
    align-items: center;
    justify-content: center;
    color: #475569;
}

.clear-search:hover {
    background: #cbd5e1;
    color: #1e293b;
}

.empty-state {
    font-size: 16px;
    text-align: center;
    padding: 60px 20px;
    color: #64748b;
}

.empty-icon {
    display: flex;
    justify-content: center;
    align-items: center;
    margin-bottom: 20px;
    color: #64748b;
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

.card-fingerprint.blurred {
    filter: blur(5px);
    cursor: pointer;
    user-select: none;
    transition: filter 0.2s ease-in-out;
}

.card-fingerprint:not(.blurred) {
    transition: filter 0.2s ease-in-out;
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
    max-width: 500px;
}

.modal h2 {
    margin: 0 0 25px;
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
    font-size: 16px;
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
    font-size: 14px;
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

.toast-icon {
    display: flex;
    align-items: center;
    justify-content: center;
}

.toast-success {
    border-left: 8px solid #10b981;
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