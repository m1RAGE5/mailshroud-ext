/**
 * Gmail integration using gmail-js library
 * This module handles DOM manipulation and Gmail UI interactions
 */

import $ from 'jquery';
import type Gmail from 'gmail-js';

// Declare global gmail instance
declare global {
  interface Window {
    Gmail: new () => Gmail;
    gmail?: Gmail;
  }
}

/**
 * Initialize Gmail.js library
 * Must be called after Gmail DOM is fully loaded
 */
export function initGmailJS(): Gmail | null {
  if (typeof window.Gmail !== 'undefined') {
    window.gmail = new window.Gmail();
    return window.gmail;
  }
  return null;
}

/**
 * Wait for Gmail DOM to be ready
 */
export function waitForGmailDOM(maxAttempts = 50, delayMs = 100): Promise<boolean> {
  return new Promise((resolve) => {
    let attempts = 0;
    
    const check = () => {
      attempts++;
      if (document.querySelector('div[role="main"]') || attempts >= maxAttempts) {
        resolve(true);
      } else {
        setTimeout(check, delayMs);
      }
    };
    
    check();
  });
}

/**
 * Extract email addresses from Gmail compose window
 */
export function getComposeRecipients(): string[] {
  const emails: string[] = [];
  
  // Try to find recipient fields in compose window
  const recipientSelectors = [
    'input[name="to"]',
    'input[name="cc"]',
    'input[name="bcc"]',
    '[data-email]' // Gmail's data attribute for contacts
  ];
  
  recipientSelectors.forEach(selector => {
    $(selector).each(function() {
      const email = $(this).attr('data-email') || $(this).val();
      if (email && typeof email === 'string' && email.includes('@')) {
        // Extract email from potential "Name <email>" format
        const match = email.match(/<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/);
        if (match) {
          emails.push(match[1].toLowerCase());
        }
      }
    });
  });
  
  // Also check for chip-style recipients (modern Gmail)
  $('.ao4 .vR').each(function() {
    const email = $(this).attr('data-email');
    if (email) {
      emails.push(email.toLowerCase());
    }
  });
  
  return [...new Set(emails)]; // Remove duplicates
}

/**
 * Get the current email thread ID
 */
export function getCurrentThreadId(): string | null {
  // Check URL first
  const urlMatch = window.location.href.match(/#inbox\/(\w+)/);
  if (urlMatch && urlMatch[1]) {
    return urlMatch[1];
  }
  
  // Try to get from Gmail.js if available
  if (window.gmail) {
    try {
      const threadId = window.gmail.get.thread_id();
      if (threadId) return threadId;
    } catch (e) {
      // Gmail.js might not have thread context
    }
  }
  
  return null;
}

/**
 * Get the current email content
 */
export function getEmailContent(): string {
  // Try various selectors for email body
  const selectors = [
    '.a3s.aiL', // Standard email body
    '.adO', // Email body container
    '[role="article"]', // Article role
    '.msg' // Legacy selector
  ];
  
  for (const selector of selectors) {
    const element = $(selector).first();
    if (element.length > 0) {
      return element.text() || element.html() || '';
    }
  }
  
  return '';
}

/**
 * Insert decrypted content into email view
 * Uses a secure container with clear visual indication
 */
export function insertDecryptedContent(
  container: HTMLElement,
  content: string,
  options?: { showBanner?: boolean; bannerText?: string }
): void {
  const $container = $(container);
  
  // Create secure wrapper
  const wrapperHtml = `
    <div class="mailshroud-decrypted" style="
      border: 2px solid #4CAF50;
      border-radius: 8px;
      padding: 16px;
      margin: 16px 0;
      background: #f1f8e9;
      font-family: Arial, sans-serif;
    ">
      ${options?.showBanner !== false ? `
        <div style="
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 12px;
          padding-bottom: 12px;
          border-bottom: 1px solid #c8e6c9;
        ">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="#4CAF50">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
          </svg>
          <span style="font-weight: bold; color: #2e7d32;">
            ${options?.bannerText || 'Mailshroud: Message Decrypted'}
          </span>
        </div>
      ` : ''}
      <div class="mailshroud-content"></div>
    </div>
  `;
  
  $container.after(wrapperHtml);
  $container.next('.mailshroud-decrypted').find('.mailshroud-content').html(content);
}

/**
 * Add encrypt button to compose window
 */
export function addEncryptButton(composeWindow: HTMLElement, onClick: () => void): void {
  const $compose = $(composeWindow);
  
  // Find the toolbar area
  const toolbar = $compose.find('.btC').first();
  if (toolbar.length === 0) return;
  
  // Check if button already exists
  if ($compose.find('.mailshroud-encrypt-btn').length > 0) return;
  
  const buttonHtml = `
    <div class="mailshroud-encrypt-btn" style="
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      margin-left: 8px;
      background: #1a73e8;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    " title="Encrypt message with PGP">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
      </svg>
      Encrypt
    </div>
  `;
  
  toolbar.append(buttonHtml);
  toolbar.find('.mailshroud-encrypt-btn').on('click', onClick);
}

/**
 * Replace compose window content with encrypted message
 */
export function setComposeContent(composeWindow: HTMLElement, content: string): void {
  const $compose = $(composeWindow);
  
  // Find the message body textarea/div
  const bodyElement = $compose.find('[aria-label="Message Body"]').first();
  
  if (bodyElement.length > 0) {
    // For textarea
    if (bodyElement.is('textarea')) {
      bodyElement.val(content);
    } else {
      // For contenteditable div
      bodyElement.text(content);
    }
    
    // Trigger input event to notify Gmail of changes
    bodyElement.trigger('input');
  }
}

/**
 * Show notification/toast in Gmail
 */
export function showNotification(message: string, type: 'success' | 'error' | 'info' = 'info'): void {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = 'mailshroud-notification';
  notification.style.cssText = `
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    padding: 12px 24px;
    border-radius: 4px;
    color: white;
    font-size: 14px;
    font-weight: 500;
    z-index: 10000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    animation: slideUp 0.3s ease-out;
    background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#1a73e8'};
  `;
  notification.textContent = message;
  
  document.body.appendChild(notification);
  
  // Remove after 4 seconds
  setTimeout(() => {
    notification.style.opacity = '0';
    notification.style.transition = 'opacity 0.3s';
    setTimeout(() => notification.remove(), 300);
  }, 4000);
}

/**
 * Detect if we're in a compose window
 */
export function isComposeWindowOpen(): boolean {
  return document.querySelector('div[role="dialog"][aria-label*="Compose"]') !== null ||
         document.querySelector('.M9') !== null;
}

/**
 * Get compose window element
 */
export function getComposeWindow(): HTMLElement | null {
  return document.querySelector('div[role="dialog"][aria-label*="Compose"]') ||
         document.querySelector('.M9');
}

/**
 * Extract PGP public key from text
 */
export function extractPublicKeyFromText(text: string): string | null {
  const pgpKeyRegex = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/;
  const match = text.match(pgpKeyRegex);
  return match ? match[0] : null;
}
