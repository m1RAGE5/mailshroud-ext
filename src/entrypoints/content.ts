/**
 * Content script that runs in isolated world
 * Handles communication between injected script and background/service worker
 */

import { db, getAllPrivateKeys, getPublicKeysByEmails } from '~/lib/db/keyDatabase';
import { decryptMessage, encryptMessage, decryptPrivateKey } from '~/lib/crypto/keyStorage';

// Track master password in memory (cleared on logout/navigation)
let cachedMasterPassword: string | null = null;

export default defineContentScript({
  matches: ['*://mail.google.com/*', '*://gmail.com/*'],
  
  async main(ctx) {
    console.log('[Mailshroud] Content script initialized');
    
    // Inject the main world script
    const injectedScript = browser.runtime.getURL('injected.js');
    
    const script = document.createElement('script');
    script.src = injectedScript;
    script.type = 'module';
    (document.head || document.documentElement).appendChild(script);
    
    // Listen for messages from the injected script
    window.addEventListener('message', async (event) => {
      if (event.source !== window) return;
      
      const data = event.data;
      
      // Handle decryption requests
      if (data?.type === 'DECRYPT_REQUEST') {
        try {
          const result = await handleDecryptRequest(data.encryptedMessage);
          window.postMessage({
            type: 'DECRYPT_RESPONSE',
            ...result
          }, '*');
        } catch (error) {
          window.postMessage({
            type: 'DECRYPT_RESPONSE',
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          }, '*');
        }
      }
      
      // Handle encryption requests
      if (data?.type === 'ENCRYPT_REQUEST') {
        try {
          const result = await handleEncryptRequest(data.message, data.publicKeys);
          window.postMessage({
            type: 'ENCRYPT_RESPONSE',
            ...result
          }, '*');
        } catch (error) {
          window.postMessage({
            type: 'ENCRYPT_RESPONSE',
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
          }, '*');
        }
      }
      
      // Handle key lookup requests
      if (data?.type === 'GET_KEYS_REQUEST') {
        try {
          const keys = await getPublicKeysByEmails(data.emails);
          window.postMessage({
            type: 'GET_KEYS_RESPONSE',
            keys
          }, '*');
        } catch (error) {
          console.error('[Mailshroud] Key lookup error:', error);
          window.postMessage({
            type: 'GET_KEYS_RESPONSE',
            keys: []
          }, '*');
        }
      }
      
      // Handle master password submission
      if (data?.type === 'MASTER_PASSWORD_SUBMIT') {
        cachedMasterPassword = data.password;
        window.postMessage({
          type: 'MASTER_PASSWORD_RESPONSE',
          success: true
        }, '*');
      }
      
      // Handle password clear
      if (data?.type === 'CLEAR_PASSWORD') {
        cachedMasterPassword = null;
        window.postMessage({
          type: 'PASSWORD_CLEARED',
          success: true
        }, '*');
      }
    });
    
    console.log('[Mailshroud] Message listeners set up');
  }
});

/**
 * Handle PGP decryption request
 */
async function handleDecryptRequest(encryptedMessage: string): Promise<{ success: boolean; decrypted?: string; error?: string }> {
  if (!cachedMasterPassword) {
    return {
      success: false,
      error: 'Master password required. Please unlock your keys first.'
    };
  }
  
  try {
    // Get all private keys
    const privateKeys = await getAllPrivateKeys();
    
    if (privateKeys.length === 0) {
      return {
        success: false,
        error: 'No private keys found. Please import your PGP key first.'
      };
    }
    
    let decrypted: string | null = null;
    let lastError: string | null = null;
    
    // Try each private key until one works
    for (const keyRecord of privateKeys) {
      try {
        // Decrypt the stored private key using master password
        const armoredPrivateKey = await decryptPrivateKey(
          {
            encrypted: keyRecord.encryptedPrivateKey,
            salt: keyRecord.salt,
            iv: keyRecord.iv
          },
          cachedMasterPassword
        );
        
        // Decrypt the message
        decrypted = await decryptMessage(encryptedMessage, armoredPrivateKey);
        break;
      } catch (error) {
        lastError = error instanceof Error ? error.message : 'Decryption failed';
        // Continue to next key
      }
    }
    
    if (decrypted) {
      return { success: true, decrypted };
    } else {
      return {
        success: false,
        error: lastError || 'Failed to decrypt with any available key'
      };
    }
  } catch (error) {
    console.error('[Mailshroud] Decryption error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Decryption failed'
    };
  }
}

/**
 * Handle PGP encryption request
 */
async function handleEncryptRequest(
  message: string,
  publicKeys: string[]
): Promise<{ success: boolean; encrypted?: string; error?: string }> {
  try {
    const encrypted = await encryptMessage(message, publicKeys);
    return { success: true, encrypted };
  } catch (error) {
    console.error('[Mailshroud] Encryption error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Encryption failed'
    };
  }
}
