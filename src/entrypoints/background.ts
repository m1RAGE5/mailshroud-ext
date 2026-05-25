export default defineBackground({
  main() {
    console.log('[Mailshroud] Background service worker initialized');
    
    // Handle installation
    browser.runtime.onInstalled.addListener((details) => {
      if (details.reason === 'install') {
        console.log('[Mailshroud] Extension installed');
        // Open options page on first install
        browser.tabs.create({ url: browser.runtime.getURL('options.html') });
      }
    });
    
    // Keep service worker alive for IndexedDB operations
    // This is needed because MV3 service workers can be terminated
    let keepAliveInterval: number | undefined;
    
    browser.runtime.onConnect.addListener((port) => {
      if (port.name === 'keepalive') {
        keepAliveInterval = setInterval(() => {
          port.postMessage({ type: 'keepalive' });
        }, 20000);
        
        port.onDisconnect.addListener(() => {
          if (keepAliveInterval) {
            clearInterval(keepAliveInterval);
          }
        });
      }
    });
  }
});
