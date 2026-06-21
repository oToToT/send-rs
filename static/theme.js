(function () {
  'use strict';

  var storageKey = 'send-theme';
  var modes = ['system', 'light', 'dark'];
  var media = window.matchMedia('(prefers-color-scheme: dark)');

  function preference() {
    try {
      var stored = localStorage.getItem(storageKey);
      return modes.indexOf(stored) >= 0 ? stored : 'system';
    } catch (_) {
      return 'system';
    }
  }

  function apply(mode) {
    var dark = mode === 'dark' || (mode === 'system' && media.matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    document.documentElement.dataset.themePreference = mode;
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    updateButton(mode, dark);
  }

  function updateButton(mode, dark) {
    var button = document.getElementById('theme-toggle');
    if (!button) return;
    var labels = {
      system: 'Theme: System',
      light: 'Theme: Light',
      dark: 'Theme: Dark'
    };
    button.setAttribute('aria-label', labels[mode]);
    button.setAttribute('title', labels[mode] + '. Click to change.');
    button.dataset.mode = mode;
    button.innerHTML = dark
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.4 15.3A8.5 8.5 0 0 1 8.7 3.6 8.5 8.5 0 1 0 20.4 15.3Z"/></svg>'
      : '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
    var indicator = document.createElement('span');
    indicator.className = 'theme-mode-indicator';
    indicator.textContent = mode === 'system' ? 'A' : '';
    button.appendChild(indicator);
  }

  function installButton() {
    var header = document.querySelector('.main-header') || document.querySelector('body > header');
    if (!header || document.getElementById('theme-toggle')) return;
    var button = document.createElement('button');
    button.id = 'theme-toggle';
    button.className = 'theme-toggle';
    button.type = 'button';
    button.addEventListener('click', function () {
      var current = preference();
      var next = modes[(modes.indexOf(current) + 1) % modes.length];
      try { localStorage.setItem(storageKey, next); } catch (_) {}
      apply(next);
    });
    header.appendChild(button);
    apply(preference());
  }

  media.addEventListener('change', function () {
    if (preference() === 'system') apply('system');
  });

  installButton();
  apply(preference());
})();
