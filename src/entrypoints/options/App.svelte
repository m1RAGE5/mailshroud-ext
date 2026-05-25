<script lang="ts">
  import { onMount } from 'svelte';
  import { db, isMasterPasswordSet, setMasterPassword, getPasswordHint, resetMasterPassword } from '~/lib/db/keyDatabase';
  import { generateKeyPair, encryptPrivateKey } from '~/lib/crypto/keyStorage';
  import type { StoredPrivateKey, StoredPublicKey } from '~/lib/db/keyDatabase';

  // State
  let masterPassword = $state('');
  let confirmPassword = $state('');
  let passwordHint = $state('');
  let isPasswordSet = $state(false);
  let userName = $state('');
  let userEmail = $state('');
  let keyPassphrase = $state('');
  let isLoading = $state(false);
  let error = $state<string | null>(null);
  let successMessage = $state<string | null>(null);
  
  // Keys state
  let privateKeys = $state<StoredPrivateKey[]>([]);
  let publicKeys = $state<StoredPublicKey[]>([]);
  let importPublicKeyText = $state('');
  let exportData = $state('');

  onMount(async () => {
    await loadKeys();
    isPasswordSet = await isMasterPasswordSet();
  });

  async function loadKeys() {
    isLoading = true;
    try {
      privateKeys = await db.privateKeys.toArray();
      publicKeys = await db.publicKeys.toArray();
    } catch (e) {
      error = 'Failed to load keys: ' + (e as Error).message;
    } finally {
      isLoading = false;
    }
  }

  async function setupMasterPassword() {
    error = null;
    successMessage = null;
    
    if (masterPassword.length < 8) {
      error = 'Password must be at least 8 characters';
      return;
    }
    
    if (masterPassword !== confirmPassword) {
      error = 'Passwords do not match';
      return;
    }
    
    isLoading = true;
    try {
      await setMasterPassword(passwordHint || undefined);
      isPasswordSet = true;
      successMessage = 'Master password set successfully!';
      masterPassword = '';
      confirmPassword = '';
      passwordHint = '';
    } catch (e) {
      error = 'Failed to set password: ' + (e as Error).message;
    } finally {
      isLoading = false;
    }
  }

  async function generateNewKey() {
    error = null;
    successMessage = null;
    
    if (!userName.trim() || !userEmail.trim()) {
      error = 'Please enter your name and email';
      return;
    }
    
    if (!isPasswordSet) {
      error = 'Please set master password first';
      return;
    }
    
    isLoading = true;
    try {
      // Generate new PGP key pair
      const { publicKey, privateKey } = await generateKeyPair(
        { name: userName, email: userEmail },
        keyPassphrase || undefined
      );
      
      // Encrypt private key with master password
      // We need to get the master password from user input for this operation
      const encrypted = await encryptPrivateKey(privateKey, masterPassword || confirmPassword);
      
      // Store in database
      await db.privateKeys.add({
        email: userEmail.toLowerCase().trim(),
        name: userName.trim(),
        publicKey,
        encryptedPrivateKey: encrypted.encrypted,
        salt: encrypted.salt,
        iv: encrypted.iv,
        createdAt: new Date(),
        isPrimary: privateKeys.length === 0 // First key becomes primary
      });
      
      successMessage = 'Key pair generated successfully!';
      await loadKeys();
      
      // Clear form
      userName = '';
      userEmail = '';
      keyPassphrase = '';
    } catch (e) {
      error = 'Failed to generate key: ' + (e as Error).message;
    } finally {
      isLoading = false;
    }
  }

  async function importPublicKey() {
    error = null;
    successMessage = null;
    
    if (!importPublicKeyText.trim()) {
      error = 'Please enter a public key';
      return;
    }
    
    isLoading = true;
    try {
      // Basic validation - check for PGP header
      if (!importPublicKeyText.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        throw new Error('Invalid public key format');
      }
      
      // Try to extract email from key (simplified - in production use openpgp.parseKey)
      const emailMatch = importPublicKeyText.match(/<([^>]+)>/);
      const email = emailMatch ? emailMatch[1] : 'unknown@example.com';
      
      await db.publicKeys.add({
        email: email.toLowerCase(),
        name: 'Imported Key',
        publicKey: importPublicKeyText.trim(),
        createdAt: new Date(),
        source: 'import'
      });
      
      successMessage = 'Public key imported successfully!';
      importPublicKeyText = '';
      await loadKeys();
    } catch (e) {
      error = 'Failed to import key: ' + (e as Error).message;
    } finally {
      isLoading = false;
    }
  }

  async function deletePrivateKey(id: number) {
    if (!confirm('Are you sure you want to delete this private key? This action cannot be undone.')) {
      return;
    }
    
    try {
      await db.privateKeys.delete(id);
      await loadKeys();
      successMessage = 'Private key deleted';
    } catch (e) {
      error = 'Failed to delete key: ' + (e as Error).message;
    }
  }

  async function deletePublicKey(id: number) {
    try {
      await db.publicKeys.delete(id);
      await loadKeys();
      successMessage = 'Public key deleted';
    } catch (e) {
      error = 'Failed to delete key: ' + (e as Error).message;
    }
  }

  async function handleResetPassword() {
    if (!confirm('WARNING: This will delete all stored private keys! Make sure you have backups. Continue?')) {
      return;
    }
    
    try {
      await resetMasterPassword();
      isPasswordSet = false;
      successMessage = 'Master password reset. All private keys have been removed.';
      privateKeys = [];
    } catch (e) {
      error = 'Failed to reset password: ' + (e as Error).message;
    }
  }

  function exportKeys() {
    const data = {
      privateKeys: privateKeys.map(k => ({ ...k })),
      publicKeys: publicKeys.map(k => ({ ...k })),
      exportedAt: new Date().toISOString()
    };
    exportData = JSON.stringify(data, null, 2);
  }

  function downloadExport() {
    if (!exportData) return;
    
    const blob = new Blob([exportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailshroud-backup-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<main>
  <h1>🔐 Mailshroud Settings</h1>
  
  {#if error}
    <div class="error">{error}</div>
  {/if}
  
  {#if successMessage}
    <div class="success">{successMessage}</div>
  {/if}
  
  <!-- Master Password Section -->
  <section class="card">
    <h2>Master Password</h2>
    
    {#if !isPasswordSet}
      <p class="description">
        Set a master password to encrypt your private keys locally. 
        This password is never stored or transmitted - forget it and you lose access to your keys!
      </p>
      
      <form onsubmit={(e) => { e.preventDefault(); setupMasterPassword(); }}>
        <div class="form-group">
          <label for="masterPassword">Master Password</label>
          <input 
            type="password" 
            id="masterPassword"
            bind:value={masterPassword}
            minlength="8"
            required
          />
        </div>
        
        <div class="form-group">
          <label for="confirmPassword">Confirm Password</label>
          <input 
            type="password" 
            id="confirmPassword"
            bind:value={confirmPassword}
            required
          />
        </div>
        
        <div class="form-group">
          <label for="passwordHint">Password Hint (optional)</label>
          <input 
            type="text" 
            id="passwordHint"
            bind:value={passwordHint}
            placeholder="Something to help you remember"
          />
        </div>
        
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Setting up...' : 'Set Master Password'}
        </button>
      </form>
    {:else}
      <p class="info">✓ Master password is set</p>
      <button class="danger" onclick={handleResetPassword}>
        Reset Master Password (deletes all private keys)
      </button>
    {/if}
  </section>
  
  <!-- Generate Key Section -->
  <section class="card">
    <h2>Generate New Key Pair</h2>
    
    {#if !isPasswordSet}
      <p class="warning">⚠️ Please set master password first</p>
    {:else}
      <form onsubmit={(e) => { e.preventDefault(); generateNewKey(); }}>
        <div class="form-group">
          <label for="userName">Your Name</label>
          <input 
            type="text" 
            id="userName"
            bind:value={userName}
            placeholder="John Doe"
            required
          />
        </div>
        
        <div class="form-group">
          <label for="userEmail">Your Email</label>
          <input 
            type="email" 
            id="userEmail"
            bind:value={userEmail}
            placeholder="john@example.com"
            required
          />
        </div>
        
        <div class="form-group">
          <label for="keyPassphrase">Key Passphrase (optional)</label>
          <input 
            type="password" 
            id="keyPassphrase"
            bind:value={keyPassphrase}
            placeholder="Additional protection for your key"
          />
        </div>
        
        <button type="submit" disabled={isLoading}>
          {isLoading ? 'Generating...' : 'Generate Key Pair'}
        </button>
      </form>
    {/if}
  </section>
  
  <!-- Import Public Key Section -->
  <section class="card">
    <h2>Import Public Key</h2>
    <p class="description">Import a contact's public key to send them encrypted emails</p>
    
    <form onsubmit={(e) => { e.preventDefault(); importPublicKey(); }}>
      <div class="form-group">
        <label for="importKey">PGP Public Key Block</label>
        <textarea 
          id="importKey"
          bind:value={importPublicKeyText}
          rows="8"
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----..."
          required
        ></textarea>
      </div>
      
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Importing...' : 'Import Public Key'}
      </button>
    </form>
  </section>
  
  <!-- Private Keys List -->
  <section class="card">
    <h2>Your Private Keys</h2>
    
    {#if privateKeys.length === 0}
      <p class="empty">No private keys stored</p>
    {:else}
      <ul class="key-list">
        {#each privateKeys as key (key.id)}
          <li class="key-item">
            <div class="key-info">
              <strong>{key.name}</strong>
              <span class="email">{key.email}</span>
              {#if key.isPrimary}
                <span class="badge">Primary</span>
              {/if}
            </div>
            <button class="danger small" onclick={() => deletePrivateKey(key.id!)}>
              Delete
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
  
  <!-- Public Keys List -->
  <section class="card">
    <h2>Stored Public Keys</h2>
    
    {#if publicKeys.length === 0}
      <p class="empty">No public keys stored</p>
    {:else}
      <ul class="key-list">
        {#each publicKeys as key (key.id)}
          <li class="key-item">
            <div class="key-info">
              <strong>{key.name}</strong>
              <span class="email">{key.email}</span>
              <span class="badge source">{key.source}</span>
            </div>
            <button class="danger small" onclick={() => deletePublicKey(key.id!)}>
              Delete
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
  
  <!-- Backup/Export Section -->
  <section class="card">
    <h2>Backup & Export</h2>
    <p class="description">Export your keys for backup purposes. Keep this file secure!</p>
    
    <div class="backup-actions">
      <button onclick={exportKeys}>Generate Backup</button>
      <button onclick={downloadExport} disabled={!exportData}>Download Backup</button>
    </div>
    
    {#if exportData}
      <details>
        <summary>View Backup Data</summary>
        <pre>{exportData}</pre>
      </details>
    {/if}
  </section>
</main>

<style>
  main {
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  
  h1 {
    color: #1a73e8;
    margin-bottom: 24px;
  }
  
  h2 {
    color: #333;
    margin-top: 0;
    font-size: 1.25rem;
  }
  
  .card {
    background: white;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  }
  
  .description {
    color: #666;
    font-size: 0.9rem;
    margin-bottom: 16px;
  }
  
  .form-group {
    margin-bottom: 16px;
  }
  
  label {
    display: block;
    margin-bottom: 6px;
    font-weight: 500;
    color: #333;
  }
  
  input, textarea {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 14px;
    box-sizing: border-box;
  }
  
  input:focus, textarea:focus {
    outline: none;
    border-color: #1a73e8;
    box-shadow: 0 0 0 2px rgba(26, 115, 232, 0.2);
  }
  
  button {
    background: #1a73e8;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
  }
  
  button:hover:not(:disabled) {
    background: #1557b0;
  }
  
  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  
  button.danger {
    background: #d93025;
  }
  
  button.danger:hover:not(:disabled) {
    background: #b02015;
  }
  
  button.small {
    padding: 6px 12px;
    font-size: 12px;
  }
  
  .error {
    background: #fce8e6;
    color: #c5221f;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
  }
  
  .success {
    background: #e6f4ea;
    color: #137333;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
  }
  
  .warning {
    background: #fef7e0;
    color: #b06000;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
  }
  
  .info {
    background: #e8f0fe;
    color: #1967d2;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
  }
  
  .key-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  
  .key-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px;
    border-bottom: 1px solid #eee;
  }
  
  .key-item:last-child {
    border-bottom: none;
  }
  
  .key-info {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  .email {
    color: #666;
    font-size: 0.9rem;
  }
  
  .badge {
    background: #1a73e8;
    color: white;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
  }
  
  .badge.source {
    background: #9aa0a6;
  }
  
  .empty {
    color: #666;
    font-style: italic;
  }
  
  .backup-actions {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
  }
  
  details {
    margin-top: 12px;
  }
  
  summary {
    cursor: pointer;
    color: #1a73e8;
  }
  
  pre {
    background: #f5f5f5;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.8rem;
    max-height: 300px;
    overflow-y: auto;
  }
</style>
