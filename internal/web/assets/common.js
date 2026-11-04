'use strict';
window.MWE = (() => {
  // DOM and display helpers
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [
    ...root.querySelectorAll(selector)
  ];
  const esc = (value) =>
    String(value ?? '').replace(
      /[&<>"']/g,
      (character) =>
        ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;'
        })[character]
    );
  const date = (value) =>
    value
      ? new Date(value).toLocaleString('zh-CN', { hour12: false })
      : '尚无记录';
  function loginURL() {
    return (
      '/login?next=' +
      encodeURIComponent(location.pathname + location.search + location.hash)
    );
  }

  function safeNext(value) {
    // Backslashes, control characters and encoded authority prefixes can be normalized by browsers.
    if (
      !value ||
      !value.startsWith('/') ||
      value.startsWith('//') ||
      /[\\\u0000-\u0020\u007f]/.test(value)
    ) {
      return '/';
    }
    try {
      const url = new URL(value, location.origin);
      return url.origin === location.origin
        ? url.pathname + url.search + url.hash
        : '/';
    } catch {
      return '/';
    }
  }
  // JSON API and session redirects
  async function api(
    path,
    { method = 'GET', body, login = true, signal } = {}
  ) {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        ...(method !== 'GET' ? { 'X-MWE-Request': '1' } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {})
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      signal
    });
    if (response.status === 401 && login) {
      location.assign(loginURL());
      throw Object.assign(new Error('登录已过期，正在跳转…'), { status: 401 });
    }
    if (response.status === 204) {
      return null;
    }
    const data = await response.json().catch(() => null);
    if (!response.ok) {
      throw Object.assign(
        new Error(data?.error?.message || '请求失败，请稍后重试。'),
        {
          status: response.status,
          code: data?.error?.code,
          retryAfter: data?.error?.retry_after_seconds
        }
      );
    }
    return data;
  }
  // Notifications and clipboard
  function toast(message) {
    const node = document.createElement('div');
    node.className = 'toast';
    node.textContent = message;
    const host = $('#toasts');
    while (host?.children.length >= 2) {
      host.firstElementChild.remove();
    }
    host?.append(node);
    setTimeout(() => node.remove(), 4500);
  }

  async function copy(value) {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('unavailable');
      }
      await navigator.clipboard.writeText(value);
      toast('已复制到剪贴板');
    } catch {
      dialog(
        '复制内容',
        /* HTML */ `
          <p>浏览器未开放剪贴板权限，请选中以下内容手动复制。</p>
          <textarea aria-label="待复制的内容" readonly>${esc(value)}</textarea>
        `,
        {
          onOpen: (node) => {
            const input = $('textarea', node);
            input.focus({ preventScroll: true });
            input.select();
          }
        }
      );
    }
  }
  // Dialog lifecycle and asynchronous forms
  let activeDialog;
  function dialog(title, content, { wide = false, onOpen, onClose } = {}) {
    activeDialog?.close();
    const previous = document.activeElement;
    const node = document.createElement('dialog');
    node.className = 'dialog' + (wide ? ' wide' : '');
    node.innerHTML = /* HTML */ `
      <div class="dialog-head">
        <h2 id="dialog-title">${esc(title)}</h2>
        <button
          type="button"
          class="button quiet small dialog-close"
          aria-label="关闭弹窗"
        >
          ✕
        </button>
      </div>
      <div class="dialog-body">${content}</div>
    `;
    node.setAttribute('aria-labelledby', 'dialog-title');
    let cleaned = false;
    function cleanup() {
      if (cleaned) {
        return;
      }
      cleaned = true;
      onClose?.();
      node.replaceChildren();
      node.remove();
      if (activeDialog?.node === node) {
        activeDialog = null;
      }
      if (previous?.isConnected) {
        previous.focus({ preventScroll: true });
      }
    }
    const close = () => {
      if (node.open) {
        node.close();
      }
      cleanup();
    };
    node.addEventListener('close', cleanup, { once: true });
    node.addEventListener('cancel', (event) => {
      event.preventDefault();
      close();
    });
    $('.dialog-close', node).onclick = close;
    node.addEventListener('click', (event) => {
      if (event.target === node) {
        const dialogBounds = node.getBoundingClientRect();
        if (
          event.clientX < dialogBounds.left ||
          event.clientX > dialogBounds.right ||
          event.clientY < dialogBounds.top ||
          event.clientY > dialogBounds.bottom
        ) {
          close();
        }
      }
    });
    document.body.append(node);
    node.showModal();
    activeDialog = { close, node };
    onOpen?.(node, close);
    return { node, close };
  }

  function bindForm(form, submit, errorSelector = '.form-error') {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (form.dataset.busy) {
        return;
      }
      const error = $(errorSelector, form);
      if (error) {
        error.hidden = true;
        error.textContent = '';
      }
      const buttons = $$('button', form);
      const disabled = buttons.map((button) => button.disabled);
      form.dataset.busy = 'true';
      buttons.forEach((button) => (button.disabled = true));
      form.setAttribute('aria-busy', 'true');
      try {
        await submit(new FormData(form));
      } catch (requestError) {
        if (error) {
          error.hidden = false;
          error.textContent = requestError.message;
        } else {
          toast(requestError.message);
        }
      } finally {
        delete form.dataset.busy;
        form.removeAttribute('aria-busy');
        buttons.forEach((button, index) => (button.disabled = disabled[index]));
      }
    });
  }

  function confirm({ title, message, label = '确认删除', action }) {
    const { node, close } = dialog(
      title,
      /* HTML */ `
        <p>${esc(message)}</p>
        <form>
          <p class="form-error error" role="alert" hidden></p>
          <div class="form-footer">
            <button type="button" class="button cancel">取消</button>
            <button type="submit" class="button primary danger">
              ${esc(label)}
            </button>
          </div>
        </form>
      `
    );
    $('.cancel', node).onclick = close;
    bindForm($('form', node), async () => {
      await action();
      close();
    });
    $('.cancel', node).focus({ preventScroll: true });
  }
  // JSON syntax highlighting
  function json(value) {
    const raw = JSON.stringify(value, null, 2) ?? 'null';
    return raw.replace(
      /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"\s*:?)|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
      (match, string, literal, number) => {
        const tokenType = string
          ? /:$/.test(match)
            ? 'key'
            : 'string'
          : literal
            ? 'literal'
            : 'number';
        // Keep replacement spans compact: whitespace here becomes part of the JSON payload view.
        return `<span class="syntax-${tokenType}">${esc(match)}</span>`;
      }
    );
  }
  // Keyboard-accessible menus
  let currentMenu;
  function menu(anchor, options, selected, choose) {
    currentMenu?.();
    const node = document.createElement('div');
    node.className = 'menu';
    node.setAttribute('role', 'menu');
    node.setAttribute(
      'aria-label',
      anchor.getAttribute('aria-label') || anchor.textContent.trim()
    );
    options.forEach((option) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.setAttribute('role', 'menuitemradio');
      button.setAttribute('aria-checked', String(option.value === selected));
      button.innerHTML = /* HTML */ `
        <span>${esc(option.label)}</span>
        <span aria-hidden="true">${option.value === selected ? '✓' : ''}</span>
      `;
      button.onclick = () => {
        close();
        choose(option.value);
      };
      node.append(button);
    });
    document.body.append(node);
    const anchorBounds = anchor.getBoundingClientRect();
    const menuBounds = node.getBoundingClientRect();
    node.style.left =
      Math.max(
        12,
        Math.min(anchorBounds.left, innerWidth - menuBounds.width - 12)
      ) + 'px';
    node.style.top =
      (anchorBounds.bottom + menuBounds.height + 8 > innerHeight
        ? Math.max(12, anchorBounds.top - menuBounds.height - 5)
        : anchorBounds.bottom + 5) + 'px';
    anchor.setAttribute('aria-expanded', 'true');
    function close(focus = true) {
      node.remove();
      anchor.setAttribute('aria-expanded', 'false');
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('keydown', keys);
      window.removeEventListener('resize', resize);
      window.removeEventListener('scroll', resize, true);
      if (focus && anchor.isConnected) {
        anchor.focus({ preventScroll: true });
      }
      if (currentMenu === close) {
        currentMenu = null;
      }
    }
    function outside(event) {
      if (!node.contains(event.target) && !anchor.contains(event.target)) {
        close(false);
      }
    }
    function resize() {
      close(false);
    }
    function keys(event) {
      const buttons = $$('button', node);
      const index = buttons.indexOf(document.activeElement);
      if (event.key === 'Escape' || event.key === 'Tab') {
        if (event.key === 'Escape') {
          event.preventDefault();
        }
        close();
      } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault();
        const target =
          event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? buttons.length - 1
              : (index +
                  (event.key === 'ArrowDown' ? 1 : -1) +
                  buttons.length) %
                buttons.length;
        buttons[target]?.focus({ preventScroll: true });
      }
    }
    document.addEventListener('pointerdown', outside);
    document.addEventListener('keydown', keys);
    window.addEventListener('resize', resize);
    window.addEventListener('scroll', resize, true);
    currentMenu = close;
    ($('[aria-checked="true"]', node) || $('button', node))?.focus({
      preventScroll: true
    });
  }
  // Saved appearance
  let appearance = 'system';
  try {
    appearance = localStorage.getItem('mwe.theme') || 'system';
  } catch {}
  const themes = [
    { value: 'system', label: '跟随系统' },
    { value: 'light', label: '浅色' },
    { value: 'dark', label: '深色' }
  ];
  function setTheme(value) {
    appearance = value;
    if (value === 'system') {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = value;
    }
    try {
      localStorage.setItem('mwe.theme', value);
    } catch {}
    updateThemeLabels();
  }

  function updateThemeLabels() {
    $$('.theme-trigger').forEach((button) => {
      button.textContent =
        themes.find((theme) => theme.value === appearance)?.label || '跟随系统';
    });
  }
  $$('.theme-trigger').forEach(
    (button) =>
      (button.onclick = () => menu(button, themes, appearance, setTheme))
  );
  updateThemeLabels();
  // Hash navigation is handled without the browser's anchor scrolling.
  document.addEventListener('click', (event) => {
    const routeLink = event.target.closest('a[href^="#/"]');
    if (
      routeLink &&
      !event.metaKey &&
      !event.ctrlKey &&
      !event.shiftKey &&
      !event.altKey &&
      event.button === 0
    ) {
      event.preventDefault();
      const next = routeLink.getAttribute('href');
      if (location.hash !== next) {
        history.pushState(null, '', next);
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      }
    }
  });
  return {
    $,
    $$,
    esc,
    date,
    api,
    toast,
    copy,
    dialog,
    bindForm,
    confirm,
    json,
    menu,
    safeNext
  };
})();
