/**
 * Website-Nexus PRO — VIP DARK GOD — @VIP_DARK_GOD
 * Main frontend utilities
 */

(function () {
  'use strict';

  // Toast notification system
  const Toast = {
    container: null,

    init() {
      this.container = document.createElement('div');
      this.container.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 9999;
        display: flex; flex-direction: column; gap: 8px;
      `;
      document.body.appendChild(this.container);
    },

    show(message, type = 'info', duration = 3500) {
      if (!this.container) this.init();

      const colors = {
        info: '#00f0ff',
        success: '#10b981',
        error: '#f43f5e',
        warning: '#f59e0b'
      };

      const el = document.createElement('div');
      el.style.cssText = `
        background: rgba(14,17,26,0.9); backdrop-filter: blur(12px);
        border: 1px solid ${colors[type] || colors.info}44;
        border-left: 3px solid ${colors[type] || colors.info};
        color: #e2e8f0; padding: 12px 18px; border-radius: 10px;
        font-size: 13px; font-weight: 500;
        box-shadow: 0 8px 30px rgba(0,0,0,0.5);
        animation: toastIn 0.3s ease;
        max-width: 360px;
      `;
      el.textContent = message;
      this.container.appendChild(el);

      setTimeout(() => {
        el.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => el.remove(), 300);
      }, duration);
    }
  };

  // Inject keyframes
  const style = document.createElement('style');
  style.textContent = `
    @keyframes toastIn {
      from { opacity: 0; transform: translateX(40px); }
      to { opacity: 1; transform: translateX(0); }
    }
    @keyframes toastOut {
      from { opacity: 1; transform: translateX(0); }
      to { opacity: 0; transform: translateX(40px); }
    }
  `;
  document.head.appendChild(style);

  // Register globally
  window.Toast = Toast;
})();
