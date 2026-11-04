'use strict';
(() => {
  const { $, $$, esc, api, bindForm, date, safeNext } = MWE;
  // Password login and rate-limit countdown
  if (document.body.dataset.page === 'login') {
    api('/api/meta', { login: false })
      .then((meta) => ($('#version').textContent = meta.version))
      .catch(() => ($('#version').textContent = 'MWE'));
    let until = 0;
    let timer;
    const button = $('#login-submit');
    const error = $('#login-error');
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((until - Date.now()) / 1000));
      button.disabled = seconds > 0;
      button.textContent = seconds ? `${seconds} 秒后重试` : '登录工作空间 →';
      if (!seconds) {
        clearInterval(timer);
      }
    };
    $('#login-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      if (button.disabled) {
        return;
      }
      button.disabled = true;
      button.textContent = '正在登录…';
      error.hidden = true;
      try {
        await api('/api/login', {
          method: 'POST',
          body: { password: $('#password').value },
          login: false
        });
        location.assign(
          safeNext(new URLSearchParams(location.search).get('next'))
        );
      } catch (requestError) {
        error.hidden = false;
        error.textContent =
          requestError.status === 401
            ? '密码不正确，请重新输入。'
            : requestError.status === 429
              ? '尝试次数过多，请在倒计时结束后重试。'
              : requestError.message;
        if (requestError.status === 429) {
          until =
            Date.now() +
            Math.max(1, Number(requestError.retryAfter) || 60) * 1000;
          clearInterval(timer);
          tick();
          timer = setInterval(tick, 250);
        } else {
          button.disabled = false;
          button.textContent = '登录工作空间 →';
          $('#password').focus({ preventScroll: true });
        }
      }
    });
    return;
  }
  // OAuth consent and identity selection
  if (document.body.dataset.page !== 'consent') {
    return;
  }
  const host = $('#consent');
  const request = new URLSearchParams(location.search).get('request');
  const path = '/api/oauth/requests/' + encodeURIComponent(request || '');
  const expired = () => {
    host.innerHTML = /* HTML */ `
      <section class="empty">
        <div class="empty-symbol" aria-hidden="true">⌁</div>
        <h1>授权请求已过期</h1>
        <p>
          请求不存在、已被使用，或已超过 10
          分钟。请回到发起接入的程序，重新开始授权。
        </p>
        <a class="button" href="/">返回工作空间</a>
      </section>
    `;
  };
  function renderConsentIdentityOption(identity, index) {
    return /* HTML */ `
      <label class="identity-option">
        <input
          type="radio"
          name="identity"
          value="${esc(identity.id)}"
          ${index === 0 ? 'checked' : ''}
        />
        <span>${esc(identity.name)}</span>
        <small>${identity.authorization_count} 个已有授权</small>
      </label>
    `;
  }

  function renderConsentClient(client) {
    const clientName = esc(client.name || '未命名客户端');
    if (client.registration !== 'cimd') {
      return `<div class="consent-client">${clientName}</div>`;
    }
    return /* HTML */ `
      <div class="consent-source">
        <strong class="consent-domain mono">${esc(client.metadata_host)}</strong>
        <span class="badge">CIMD</span>
        <span class="consent-client-name">${clientName}</span>
      </div>
      <p class="hint consent-disclaimer">
        名称由该网站上的文档自称，未经平台审核。请核对来源域名。
      </p>
      <details>
        <summary>查看客户端 ID</summary>
        <code class="break">${esc(client.id)}</code>
      </details>
    `;
  }

  function renderConsentWarning(warning) {
    const message = warning.code === 'localhost_redirect'
      ? '该应用用网址标识自己，却要将你重定向回本机地址。' +
        '本机上的其他程序可能冒充它，请确认这是你发起接入的程序。'
      : warning.message;
    return /* HTML */ `
      <div class="notice warning consent-warning" role="note">
        <strong>接入风险提示</strong>
        <p>${esc(message)}</p>
      </div>
    `;
  }

  async function start() {
    if (!request) {
      expired();
      return;
    }
    try {
      const data = await api(path);
      const client = data.client;
      const normalized = String(client.redirect_host)
        .toLowerCase()
        .replace(/^\[|\]$/g, '')
        .replace(/\.$/, '');
      const loopback =
        normalized === 'localhost' ||
        normalized.endsWith('.localhost') ||
        normalized === '::1' ||
        /^127(?:\.\d{1,3}){3}$/.test(normalized);
      host.innerHTML = /* HTML */ `
        <h1>允许这个程序接入？</h1>
        <p class="muted" style="margin-top:8px">
          确认程序与身份，授权后即可管理接入并接收事件。
        </p>
        <div class="consent-flow">
          <div class="hint">发起接入的程序</div>
          ${renderConsentClient(client)}
          <div class="consent-host">
            回调至
            <strong class="mono">${esc(client.redirect_host)}</strong>
            ${loopback ? '<span class="badge green">本机应用</span>' : ''}
          </div>
          <details>
            <summary>查看完整回调地址</summary>
            <code class="break">${esc(client.redirect_uri)}</code>
          </details>
          ${(client.warnings || []).map(renderConsentWarning).join('')}
          <div class="flow-arrow" aria-hidden="true">↓</div>
          <div class="hint">将以此 Agent Identity 的身份接入</div>
          <div class="target" id="identity-target"></div>
        </div>
        <form id="consent-form">
          <fieldset>
            <legend>选择接入身份</legend>
            <div class="consent-options">
              ${(data.identities || []).map(renderConsentIdentityOption).join('')}
              <label class="identity-option">
                <input
                  type="radio"
                  name="identity"
                  value="_new"
                  ${!data.identities?.length ? 'checked' : ''}
                />
                <span>＋ 新建 Agent Identity</span>
              </label>
            </div>
          </fieldset>
          <div class="field" id="new-identity-field">
            <label for="identity-name">新 Identity 名称</label>
            <input
              id="identity-name"
              name="new_identity_name"
              maxlength="64"
              placeholder="例如：工作笔记本上的 Agent"
              autocomplete="off"
            />
          </div>
          <ul class="consent-permissions">
            <li>管理所选身份的 Webhooks 与 Channels</li>
            <li>订阅并接收该身份的事件和平台广播</li>
          </ul>
          <p class="hint break">接入资源：${esc(data.resource)}</p>
          <p class="form-error error" role="alert" hidden></p>
          <div class="form-footer">
            <button id="deny" type="button" class="button">拒绝</button>
            <button type="submit" class="button primary">批准接入 →</button>
          </div>
          <p class="consent-expiry">
            请求有效至 ${esc(date(data.expires_at))}。可随时在工作空间撤销授权。
          </p>
        </form>
      `;
      const form = $('#consent-form');
      const name = $('#identity-name');
      function update() {
        const value = $('input[name="identity"]:checked', form)?.value;
        const fresh = value === '_new';
        $('#new-identity-field').hidden = !fresh;
        name.required = fresh;
        name.disabled = !fresh;
        $('#identity-target').textContent = fresh
          ? name.value.trim() || '新 Agent Identity'
          : data.identities.find(
              (candidateIdentity) => candidateIdentity.id === value
            )?.name || '请选择身份';
      }
      form.addEventListener('change', update);
      name.addEventListener('input', update);
      update();
      async function send(kind, body) {
        try {
          const result = await api(path + '/' + kind, {
            method: 'POST',
            ...(body ? { body } : {})
          });
          location.assign(result.redirect_url);
        } catch (requestError) {
          if (requestError.status === 404) {
            expired();
          }
          throw requestError;
        }
      }
      bindForm(form, async (formData) => {
        const value = formData.get('identity');
        await send(
          'approve',
          value === '_new'
            ? {
                new_identity_name: String(
                  formData.get('new_identity_name')
                ).trim()
              }
            : { identity_id: value }
        );
      });
      $('#deny').onclick = async () => {
        const buttons = $$('button', form);
        buttons.forEach((button) => (button.disabled = true));
        try {
          await send('deny');
        } catch (requestError) {
          if (form.isConnected) {
            const error = $('.form-error', form);
            error.hidden = false;
            error.textContent = requestError.message;
            buttons.forEach((button) => (button.disabled = false));
          }
        }
      };
    } catch (requestError) {
      if (requestError.status === 404) {
        expired();
      } else if (requestError.status !== 401) {
        host.innerHTML = /* HTML */ `
          <section class="empty">
            <h1>暂时无法读取授权请求</h1>
            <p class="error" role="alert">${esc(requestError.message)}</p>
            <button class="button" id="retry-consent">重试</button>
          </section>
        `;
      }
      $('#retry-consent')?.addEventListener('click', start);
    }
  }
  start();
})();
