<script lang="ts">
    import { messenger } from "~/lib/messaging";
    import type { KeyInfo } from "~/lib/types/messages";

    // Svelte 5 Runes
    let isUnlocked = $state(false);
    let isLoading = $state(true);
    let isUnlocking = $state(false);
    let password = $state("");
    let error = $state("");
    let keys = $state<KeyInfo[]>([]);

    // При завантаженні Popup перевіряємо поточний стан Vault у Background
    $effect(() => {
        checkStatus();
    });

    async function checkStatus() {
        isLoading = true;
        try {
            isUnlocked = await messenger.sendMessage("isVaultUnlocked", undefined);
            if (isUnlocked) {
                keys = await messenger.sendMessage("listPrivateKeys", undefined);
            } else {
                keys = [];
            }
        } catch (err) {
            console.error("Status check failed:", err);
        } finally {
            isLoading = false;
        }
    }

    async function handleUnlock(e: Event) {
        e.preventDefault();
        if (!password) return;
        
        isUnlocking = true;
        error = "";
        
        try {
            const result = await messenger.sendMessage("unlockVault", password);
            
            if (result.success) {
                isUnlocked = true;
                password = ""; // Очищуємо пароль з пам'яті UI
                keys = await messenger.sendMessage("listPrivateKeys", undefined);
            } else {
                error = `Не вдалося розблокувати. Помилки: ${result.failedEmails.join(", ")}`;
            }
        } catch (err: any) {
            // Обробка помилок від Background (VaultError)
            if (err?.code === "INVALID_PASSWORD") {
                error = "Невірний Master Password.";
            } else if (err?.code === "VAULT_RATE_LIMITED") {
                error = "Занадто багато спроб. Зачекайте.";
            } else {
                error = err?.message || "Сталася невідома помилка.";
            }
        } finally {
            isUnlocking = false;
        }
    }

    async function handleLock() {
        await messenger.sendMessage("lockVault", undefined);
        isUnlocked = false;
        keys = [];
        password = ""; // Очищуємо поле вводу
    }
</script>

<main>
    <header>
        <h1>🛡️ MailShroud</h1>
    </header>

    {#if isLoading}
        <div class="loader">Перевірка стану Vault...</div>
    {:else if isUnlocked}
        <div class="status unlocked">
            <span class="dot"></span> Vault Розблоковано
        </div>
        
        <section class="keys">
            <h2>Ваші ключі ({keys.length})</h2>
            {#if keys.length === 0}
                <p class="empty">Приватні ключі відсутні.</p>
            {:else}
                <ul>
                    {#each keys as key}
                        <li>
                            <strong>{key.email}</strong>
                            <code title={key.fingerprint}>...{key.fingerprint.slice(-8).toUpperCase()}</code>
                        </li>
                    {/each}
                </ul>
            {/if}
        </section>

        <button onclick={handleLock} class="btn btn-danger">
            Заблокувати Vault
        </button>
    {:else}
        <div class="status locked">
            <span class="dot"></span> Vault Заблоковано
        </div>
        
        <form onsubmit={handleUnlock}>
            <label for="pwd">Master Password</label>
            <!-- svelte-ignore a11y_autofocus -->
            <input 
                id="pwd" 
                type="password" 
                bind:value={password} 
                placeholder="Введіть пароль"
                autocomplete="off"
                autofocus
            />
            {#if error}
                <p class="error">{error}</p>
            {/if}
            <button type="submit" class="btn btn-primary" disabled={isUnlocking || !password}>
                {isUnlocking ? "Розблокування..." : "Розблокувати"}
            </button>
        </form>
    {/if}
</main>

<style>
    main { padding: 20px; display: flex; flex-direction: column; gap: 16px; }
    h1 { font-size: 22px; margin: 0; text-align: center; letter-spacing: -0.5px; }
    h2 { font-size: 12px; margin: 0 0 10px; color: #a1a1aa; text-transform: uppercase; letter-spacing: 1px; }
    
    .status { display: flex; align-items: center; gap: 10px; font-weight: 500; font-size: 14px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; }
    .unlocked .dot { background: #10b981; box-shadow: 0 0 10px #10b981; }
    .locked .dot { background: #ef4444; box-shadow: 0 0 10px #ef4444; }
    
    form { display: flex; flex-direction: column; gap: 12px; }
    label { font-size: 13px; color: #a1a1aa; }
    input {
        padding: 12px; border-radius: 8px; border: 1px solid #3f3f46; 
        background: #27272a; color: white; font-size: 14px;
    }
    input:focus { outline: none; border-color: #10b981; }
    
    .btn {
        padding: 12px; border: none; border-radius: 8px; font-weight: 600; 
        cursor: pointer; font-size: 14px; transition: all 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #10b981; color: white; }
    .btn-primary:hover:not(:disabled) { background: #059669; }
    .btn-danger { background: #3f3f46; color: #ef4444; border: 1px solid #ef4444; }
    .btn-danger:hover { background: #ef4444; color: white; }
    
    .keys ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 10px; }
    .keys li {
        background: #27272a; padding: 12px; border-radius: 8px; 
        border: 1px solid #3f3f46; font-size: 13px;
    }
    .keys code { display: block; font-family: monospace; color: #71717a; margin-top: 6px; font-size: 11px; }
    
    .error { color: #ef4444; font-size: 13px; margin: 0; background: #27272a; padding: 8px; border-radius: 6px; }
    .empty { font-size: 13px; color: #71717a; font-style: italic; text-align: center; padding: 20px 0; }
    .loader { text-align: center; color: #71717a; padding: 40px 0; }
</style>