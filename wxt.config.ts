import { defineConfig } from 'wxt';

// See https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: 'src',
  modules: ['@wxt-dev/module-svelte'],
  manifest: {
    permissions: ['storage', 'activeTab'],
    host_permissions: ['*://mail.google.com/*', '*://gmail.com/*'],
    web_accessible_resources: [
      {
        resources: ['injected.js'],
        matches: ['*://mail.google.com/*', '*://gmail.com/*']
      }
    ]
  },
});
