(() => {
  'use strict';
  const form = document.getElementById('login-form');
  const error = document.getElementById('login-error');
  if (!form || !error) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.textContent = '';
    const username = document.getElementById('login-username');
    const password = document.getElementById('login-password');
    try {
      const response = await fetch('/login', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.value, password: password.value })
      });
      password.value = '';
      if (response.status === 204) { window.location.replace('/'); return; }
      error.textContent = response.status === 401 ? 'Invalid credentials.' : 'Sign in is unavailable. Try again.';
    } catch (_) { password.value = ''; error.textContent = 'Sign in is unavailable. Try again.'; }
  });
})();
