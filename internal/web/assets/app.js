'use strict';
(() => {
  const {
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
    menu
  } = MWE;
  // Workspace state and shared form markup
  const main = $('#main');
  let identities = [];
  let identitiesLoaded = false;
  let identitiesRevision = 0;
  let identitiesRequest;
  let currentView;
  const tabCache = new Map();
  const regions = new Map();
  const loadingDelay = 180;
  let eventSource;
  let eventsState;
  const normalPattern = '[a-z0-9]+(-[a-z0-9]+)*';
  const reservedPattern = ':[a-z0-9](?:[a-z0-9:]|-)*';
  const identityAPIPath = (identityId) =>
    '/api/identities/' + encodeURIComponent(identityId);
  const identityRoute = (identityId) =>
    '#/identities/' + encodeURIComponent(identityId);
  const formErrorMarkup =
    '<p class="form-error error" role="alert" hidden></p>';
  function formActions(primary = '保存') {
    return (
      formErrorMarkup +
      /* HTML */ `
      <div class="form-footer">
        <button type="button" class="button cancel">取消</button>
        <button type="submit" class="button primary">${primary}</button>
      </div>
    `
    );
  }

  function renderField(
    label,
    name,
    value = '',
    {
      hint = '',
      required = false,
      pattern,
      maxlength,
      type = 'text',
      readonly = false,
      placeholder = ''
    } = {}
  ) {
    return /* HTML */ `
      <div class="field">
        <label for="field-${name}">${label}</label>
        <input
          id="field-${name}"
          name="${name}"
          type="${type}"
          value="${esc(value)}"
          ${required ? 'required' : ''}
          ${readonly ? 'readonly' : ''}
          ${pattern ? `pattern="${esc(pattern)}"` : ''}
          ${maxlength ? `maxlength="${maxlength}"` : ''}
          placeholder="${esc(placeholder)}"
          ${hint ? `aria-describedby="hint-${name}"` : ''}
        />
        ${
          hint
            ? /* HTML */ `
                <span class="hint" id="hint-${name}">${hint}</span>
              `
            : ''
        }
      </div>
    `;
  }

  function renderDescriptionField(value = '') {
    return /* HTML */ `
      <div class="field">
        <label for="field-description">
          说明
          <span class="muted">（可选）</span>
        </label>
        <textarea id="field-description" name="description" rows="3">${esc(value)}</textarea>
      </div>
    `;
  }

  function formDialog(title, content, submit) {
    const { node, close } = dialog(
      title,
      /* HTML */ `
        <form>${content}${formActions()}</form>
      `
    );
    $('.cancel', node).onclick = close;
    bindForm($('form', node), async (formData) => {
      await submit(formData, close);
    });
    return node;
  }

  function renderEmptyState(title, message, button = '') {
    return /* HTML */ `
      <div class="empty">
        <div class="empty-symbol" aria-hidden="true">◇</div>
        <h2>${title}</h2>
        <p>${message}</p>
        ${button}
      </div>
    `;
  }

  // Each region owns its request, delayed feedback, and retry. Old content stays interactive.
  function cancelRegion(host) {
    const request = regions.get(host);
    if (!request) {
      return;
    }
    request.controller.abort();
    clearTimeout(request.timer);
    request.status.remove();
    host.removeAttribute('aria-busy');
    host.classList.remove('refreshing');
    regions.delete(host);
  }

  async function loadRegion(
    host,
    label,
    load,
    apply,
    populated = false,
    options = {}
  ) {
    const { background = false, retry } = options;
    cancelRegion(host);
    const previousError = host.querySelector(':scope > .region-error');
    if (previousError?.contains(document.activeElement)) {
      host.setAttribute('tabindex', '-1');
      host.focus({ preventScroll: true });
    }
    previousError?.remove();
    const controller = new AbortController();
    const status = document.createElement('div');
    status.className = populated ? 'region-status' : 'loading region-status';
    status.setAttribute('role', 'status');
    const request = { controller, status };
    regions.set(host, request);
    if (!background) {
      host.setAttribute('aria-busy', 'true');
    }
    request.timer = setTimeout(() => {
      if (background || regions.get(host) !== request || !host.isConnected) {
        return;
      }
      status.textContent = populated ? '正在刷新…' : `正在加载${label}…`;
      host.classList.toggle('refreshing', populated);
      host.append(status);
    }, loadingDelay);
    try {
      const data = await load(controller.signal);
      if (regions.get(host) === request && host.isConnected) {
        apply(data);
      }
    } catch (requestError) {
      if (
        regions.get(host) === request &&
        host.isConnected &&
        requestError.name !== 'AbortError' &&
        requestError.status !== 401
      ) {
        const error = document.createElement('div');
        error.className = 'notice warning region-error';
        error.innerHTML = /* HTML */ `
          <p class="error" role="alert">
            ${esc(label)}加载失败：${esc(requestError.message)}
          </p>
          <button class="button" type="button">重试</button>
        `;
        $('button', error).onclick =
          retry ||
          (() => loadRegion(host, label, load, apply, populated, options));
        host.append(error);
      }
    } finally {
      if (regions.get(host) === request) {
        cancelRegion(host);
      }
    }
  }

  // Reconcile keyed rows so unchanged rows, focused controls and open details survive refreshes.
  function patchRows(host, markup) {
    const template = document.createElement('template');
    template.innerHTML = markup;
    const previous = new Map(
      [...host.children]
        .filter((node) => node.dataset.rowKey)
        .map((node) => [node.dataset.rowKey, node])
    );
    const focused = host.contains(document.activeElement)
      ? document.activeElement
      : null;
    const focusAttributes = focused
      ? [...focused.attributes].filter(
          (attribute) =>
            attribute.name === 'id' || attribute.name === 'href' || attribute.name.startsWith('data-')
        )
      : [];
    let cursor = host.firstElementChild;
    for (const next of [...template.content.children]) {
      const existing = previous.get(next.dataset.rowKey);
      if (existing) {
        $$('details', existing).forEach((details, index) => {
          if (details.open && $$('details', next)[index]) {
            $$('details', next)[index].open = true;
          }
        });
      }
      const node = existing?.outerHTML === next.outerHTML ? existing : next;
      if (node !== cursor) {
        host.insertBefore(node, cursor);
      }
      cursor = node.nextElementSibling;
    }
    while (cursor) {
      const next = cursor.nextElementSibling;
      cursor.remove();
      cursor = next;
    }
    if (focused && !focused.isConnected) {
      const replacement = focusAttributes.length
        ? $$('button, a', host).find((candidate) =>
            focusAttributes.every(
              ({ name, value }) => candidate.getAttribute(name) === value
            )
          )
        : null;
      const fallback = $('.section-caption button', host.parentElement);
      (replacement || fallback)?.focus({ preventScroll: true });
    }
  }

  function resourceMarkup(host, markup) {
    if (!host.querySelector('.section-caption')) {
      host.innerHTML = markup;
      return;
    }
    const template = document.createElement('template');
    template.innerHTML = markup;
    $('.section-caption span', host).textContent = $(
      '.section-caption span',
      template.content
    ).textContent;
    patchRows(
      $('section.list', host),
      $('section.list', template.content).innerHTML
    );
  }

  function navigate(hash) {
    if (location.hash !== hash) {
      history.pushState(null, '', hash);
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    } else {
      renderPage();
    }
  }

  function renderPageHeader(title, subtitle, button = '') {
    return /* HTML */ `
      <div class="page-head">
        <div>
          <h1>${esc(title)}</h1>
          <p>${esc(subtitle)}</p>
        </div>
        ${button}
      </div>
    `;
  }
  // Identity list and detail navigation
  function openIdentityForm(identity) {
    formDialog(
      identity ? '重命名 Identity' : '新建 Agent Identity',
      renderField('名称', 'name', identity?.name, {
        required: true,
        maxlength: 64,
        placeholder: '例如：工作笔记本上的 Agent',
        hint: '用名称区分不同设备、程序或用途。'
      }),
      async (formData, close) => {
        const name = String(formData.get('name')).trim();
        if (!name) {
          throw new Error('请输入 Identity 名称。');
        }
        const result = await api(
          identity ? identityAPIPath(identity.id) : '/api/identities',
          {
            method: identity ? 'PATCH' : 'POST',
            body: { name }
          }
        );
        close();
        toast(identity ? '名称已更新' : 'Identity 已创建');
        identitiesRevision++;
        identitiesRequest?.controller.abort();
        identitiesRequest = null;
        const index = identities.findIndex(
          (candidate) => candidate.id === result.id
        );
        if (index < 0) {
          identities.push(result);
        } else {
          identities[index] = result;
        }
        updateIdentityNames();
        if (!identity) {
          navigate(identityRoute(result.id));
        }
      }
    );
  }

  function deleteIdentity(identity) {
    confirm({
      title: '删除这个 Identity？',
      message:
        `将永久删除「${identity.name}」` +
        '及其所有 Webhooks、Channels、授权、订阅和事件。' +
        '此操作无法撤销。',
      action: async () => {
        await api(identityAPIPath(identity.id), { method: 'DELETE' });
        identitiesRevision++;
        identitiesRequest?.controller.abort();
        identitiesRequest = null;
        identities = identities.filter(
          (candidate) => candidate.id !== identity.id
        );
        tabCache.delete(identity.id);
        toast('Identity 及关联数据已删除');
        navigate('#/identities');
      }
    });
  }

  function renderIdentityRow(identity) {
    return /* HTML */ `
      <div class="identity-row" data-row-key="${esc(identity.id)}">
        <div class="identity-icon" aria-hidden="true">
          ${esc(identity.name.slice(0, 1).toUpperCase())}
        </div>
        <div class="identity-info">
          <a class="identity-name" href="${identityRoute(identity.id)}">
            ${esc(identity.name)}
          </a>
          <div class="identity-id">${esc(identity.id)}</div>
        </div>
        <div class="identity-stats">
          <span>
            <b>${identity.webhook_count}</b>
            Webhooks
          </span>
          <span>
            <b>${identity.channel_count}</b>
            Channels
          </span>
          <span>
            <b>${identity.authorization_count}</b>
            授权
          </span>
        </div>
        <a
          class="button quiet small row-end"
          href="${identityRoute(identity.id)}"
          aria-label="管理 ${esc(identity.name)}"
        >
          管理 ↗
        </a>
      </div>
    `;
  }

  function renderIdentities() {
    main.innerHTML =
      renderPageHeader(
        'Agent Identity',
        '为每个 Agent 建立独立的接入身份，集中管理它的事件来源和投递。',
        '<button class="button primary" id="create-identity">＋ 新建 Identity</button>'
      ) +
      /* HTML */ `
        <div class="section-caption">
          <span id="identity-count"></span>
          <span>独立授权 · 独立事件空间</span>
        </div>
        <section
          class="list"
          id="identity-list"
          aria-label="Identity 列表"
        ></section>
        <p class="bottom-note">
          Identity 是 Agent 的权限边界。同一个身份可以授权给多个客户端。
        </p>
      `;
    $('#create-identity').onclick = () => openIdentityForm();
    updateIdentityNames();
  }

  function updateIdentityNames() {
    const list = $('#identity-list');
    if (list && identitiesLoaded) {
      $('#identity-count').textContent = `${identities.length} 个身份`;
      patchRows(
        list,
        identities.length
          ? identities.map(renderIdentityRow).join('')
          : renderEmptyState(
              '从一个身份开始',
              '新建 Identity 后，可以配置 Webhook，或让 Agent 在 OAuth 授权时选择它。',
              '<button class="button" id="empty-create">新建 Identity</button>'
            )
      );
      $('#empty-create')?.addEventListener('click', () => openIdentityForm());
    }
    if (currentView?.identityId) {
      const identity = identities.find(
        (candidate) => candidate.id === currentView.identityId
      );
      if (identity) {
        $('.page-head h1').textContent = identity.name;
        $('.page-head p').textContent = '创建于 ' + date(identity.created_at);
        $('.breadcrumb span:last-child').textContent = identity.name;
        $('#rename-identity').disabled = false;
        $('#delete-identity').disabled = false;
        $('#rename-identity').onclick = () => openIdentityForm(identity);
        $('#delete-identity').onclick = () => deleteIdentity(identity);
      }
    }
    eventsState?.updateIdentityFilter();
  }

  function requestIdentities() {
    if (identitiesRequest) {
      return identitiesRequest.promise;
    }
    const controller = new AbortController();
    const revision = identitiesRevision;
    const request = { controller };
    request.promise = api('/api/identities', { signal: controller.signal })
      .then((data) => {
        if (revision === identitiesRevision && !controller.signal.aborted) {
          identities = data.identities || [];
          identitiesLoaded = true;
          updateIdentityNames();
        }
      })
      .finally(() => {
        if (identitiesRequest === request) {
          identitiesRequest = null;
        }
      });
    identitiesRequest = request;
    return request.promise;
  }

  function refreshIdentities() {
    const host = $('#identity-list') || $('#identity-summary');
    if (host) {
      return loadRegion(
        host,
        'Identity',
        () => requestIdentities(),
        () => {
          if (
            currentView?.identityId &&
            !identities.some(
              (identity) => identity.id === currentView.identityId
            )
          ) {
            host.innerHTML = renderEmptyState(
              '找不到这个 Identity',
              '它可能已被删除。'
            );
          }
        },
        identitiesLoaded,
        { background: !!currentView?.identityId && identitiesLoaded }
      );
    }
    // Events do not depend on the identity directory to start loading their history.
    return eventsState?.refreshIdentities();
  }
  const tabs = [
    ['webhooks', 'Webhooks'],
    ['channels', 'Channels'],
    ['authorizations', '授权'],
    ['subscriptions', '订阅']
  ];
  function renderIdentityBreadcrumb(identity) {
    return /* HTML */ `
      <div class="breadcrumb">
        <a href="#/identities">Agent Identity</a>
        <span>/</span>
        <span>${esc(identity.name)}</span>
      </div>
    `;
  }

  function renderIdentity(identityId, tab) {
    if (currentView?.identityId !== identityId) {
      currentView = { page: 'identities', identityId };
      const identity = identities.find(
        (candidate) => candidate.id === identityId
      );
      main.innerHTML =
        renderIdentityBreadcrumb(identity || { name: 'Identity' }) +
        renderPageHeader(
          identity?.name || 'Identity',
          identity ? '创建于 ' + date(identity.created_at) : '',
          /* HTML */ `
            <div class="actions">
              <button id="rename-identity" class="button" disabled>
                重命名
              </button>
              <button id="delete-identity" class="button quiet danger" disabled>
                删除 Identity
              </button>
            </div>
          `
        ) +
        /* HTML */ `
          <div id="identity-summary"></div>
          <nav class="tabs" aria-label="Identity 详情">
            ${tabs
              .map(
                ([value, label]) => /* HTML */ `
                  <a
                    href="${identityRoute(identityId)}/${value}"
                    data-tab="${value}"
                  >
                    ${label}
                  </a>
                `
              )
              .join('')}
          </nav>
          <div id="tab-content" class="data-region"></div>
        `;
      updateIdentityNames();
    }
    if (!tabs.some(([value]) => value === tab)) {
      tab = 'webhooks';
    }
    $$('.tabs a').forEach((link) => {
      if (link.dataset.tab === tab) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    });
    const content = $('#tab-content');
    if (currentView.tab !== tab) {
      cancelRegion(content);
      regions.forEach((request, host) => {
        if (content.contains(host)) {
          cancelRegion(host);
        }
      });
      content.replaceChildren();
      currentView.tab = tab;
      const cached = tabCache.get(identityId)?.[tab];
      if (cached) {
        drawTab(content, identityId, tab, cached);
      }
    }
    return refreshTab(identityId, tab, false);
  }

  function drawTab(host, identityId, tab, items) {
    ({
      webhooks: renderWebhooks,
      channels: renderChannels,
      authorizations: renderAuthorizations,
      subscriptions: renderSubscriptions
    })[tab](host, identityId, items);
  }

  function refreshTab(identityId, tab, invalidate = true) {
    const cached = tabCache.get(identityId) || {};
    if (invalidate) {
      delete cached[tab];
    }
    tabCache.set(identityId, cached);
    if (currentView?.identityId !== identityId || currentView.tab !== tab) {
      return;
    }
    const content = $('#tab-content');
    const list = $('section.list', content);
    return loadRegion(
      list || content,
      tabs.find(([value]) => value === tab)[1],
      (signal) => api(identityAPIPath(identityId) + '/' + tab, { signal }),
      (data) => {
        const items = data[tab] || [];
        cached[tab] = items;
        drawTab(content, identityId, tab, items);
        const identity = identities.find(
          (candidate) => candidate.id === identityId
        );
        const countField = {
          webhooks: 'webhook_count',
          channels: 'channel_count',
          authorizations: 'authorization_count'
        }[tab];
        if (identity && countField) {
          identity[countField] = items.length;
        }
      },
      !!list
    );
  }
  // Webhook management and one-time keys
  function renderWebhookRow(webhook) {
    return /* HTML */ `
      <article class="resource" data-row-key="${esc(webhook.id)}">
        <div class="resource-head">
          <div>
            <div class="resource-heading">
              <h3>${esc(webhook.name || webhook.identifier)}</h3>
              <span class="badge">${esc(webhook.identifier)}</span>
            </div>
            ${
              webhook.description
                ? /* HTML */ `
                    <p>${esc(webhook.description)}</p>
                  `
                : ''
            }
          </div>
          <div class="actions">
            <button
              class="button quiet small"
              data-wh-edit="${esc(webhook.id)}"
            >
              编辑
            </button>
            <button class="button quiet small" data-wh-key="${esc(webhook.id)}">
              轮换 key
            </button>
            <button
              class="button quiet small danger"
              data-wh-delete="${esc(webhook.id)}"
            >
              删除
            </button>
          </div>
        </div>
        <div class="copy-line">
          <code>${esc(webhook.url)}</code>
          <button
            class="button small"
            data-wh-copy="${esc(webhook.id)}"
            aria-label="复制 ${esc(webhook.identifier)} URL"
          >
            复制 URL
          </button>
        </div>
        <div class="resource-meta">
          <span>${webhook.event_count} 条事件</span>
          <span>最近事件：${esc(date(webhook.last_event_at))}</span>
        </div>
      </article>
    `;
  }

  function renderWebhooks(host, identityId, items) {
    resourceMarkup(host, /* HTML */ `
      <div class="section-caption">
        <span>${items.length} 个事件来源</span>
        <button class="button primary" id="create-webhook">
          ＋ 新建 Webhook
        </button>
      </div>
      <section class="list" aria-label="Webhooks">
        ${
          items.length
            ? items.map(renderWebhookRow).join('')
            : renderEmptyState(
                '还没有 Webhook',
                '创建后，将 URL 和 key 配置到事件来源。收到的请求会出现在事件流中。'
              )
        }
      </section>
    `);
    const find = (webhookId) =>
      items.find((candidateWebhook) => candidateWebhook.id === webhookId);
    $('#create-webhook', host).onclick = () => openWebhookForm(identityId);
    $$('[data-wh-copy]', host).forEach(
      (button) => (button.onclick = () => copy(find(button.dataset.whCopy).url))
    );
    $$('[data-wh-edit]', host).forEach(
      (button) =>
        (button.onclick = () =>
          openWebhookForm(identityId, find(button.dataset.whEdit)))
    );
    $$('[data-wh-delete]', host).forEach(
      (button) =>
        (button.onclick = () => {
          const webhook = find(button.dataset.whDelete);
          confirm({
            title: '删除 Webhook？',
            message:
              `「${webhook.name || webhook.identifier}」的 URL 将立即失效，` +
              '事件来源将无法继续投递。',
            action: async () => {
              await api(
                identityAPIPath(identityId) +
                  '/webhooks/' +
                  encodeURIComponent(webhook.id),
                { method: 'DELETE' }
              );
              toast('Webhook 已删除');
              refreshTab(identityId, 'webhooks');
            }
          });
        })
    );
    $$('[data-wh-key]', host).forEach(
      (button) =>
        (button.onclick = () => {
          const webhook = find(button.dataset.whKey);
          confirm({
            title: '轮换 Webhook key？',
            message:
              '旧 key 会立即失效。请在轮换后更新事件来源使用的 key，新 key 只显示一次。',
            label: '轮换 key',
            action: async () => {
              const result = await api(
                identityAPIPath(identityId) +
                  '/webhooks/' +
                  encodeURIComponent(webhook.id) +
                  '/rotate-key',
                { method: 'POST' }
              );
              showWebhookKey(result);
              refreshTab(identityId, 'webhooks');
            }
          });
        })
    );
  }

  function openWebhookForm(identityId, webhook) {
    formDialog(
      webhook ? '编辑 Webhook' : '新建 Webhook',
      (webhook
        ? renderField('事件 identifier', 'identifier', webhook.identifier, {
            readonly: true,
            hint: '创建后不可修改。'
          })
        : renderField('事件 identifier', 'identifier', '', {
            required: true,
            pattern: normalPattern,
            maxlength: 64,
            placeholder: 'github-push',
            hint: '小写字母、数字和连接用的短横线，最长 64 字符。'
          })) +
        renderField('显示名称', 'name', webhook?.name, {
          placeholder: '例如：GitHub push'
        }) +
        renderDescriptionField(webhook?.description),
      async (formData, close) => {
        const body = {
          name: String(formData.get('name')).trim(),
          description: String(formData.get('description')).trim()
        };
        if (!webhook) {
          body.identifier = String(formData.get('identifier'));
        }
        const result = await api(
          identityAPIPath(identityId) +
            '/webhooks' +
            (webhook ? '/' + encodeURIComponent(webhook.id) : ''),
          { method: webhook ? 'PATCH' : 'POST', body }
        );
        close();
        if (webhook) {
          toast('Webhook 已更新');
        } else {
          showWebhookKey(result);
        }
        refreshTab(identityId, 'webhooks');
      }
    );
  }

  function showWebhookKey(result) {
    // The key lives only in this dialog closure and DOM, never in application state or storage.
    let key = result.key;
    const webhook = result.webhook;
    result.key = null;
    const shellQuote = (value) =>
      "'" + String(value).replace(/'/g, "'\\''") + "'";
    const curl = [
      `curl -X POST ${shellQuote(webhook.url)} \\`,
      `  -H ${shellQuote('X-Webhook-Key: ' + key)} \\`,
      "  -H 'Content-Type: application/json' \\",
      `  -d '{"message":"hello"}'`
    ].join('\n');
    const keyUsage = [
      `X-Webhook-Key: ${esc(key)}`,
      '',
      `Authorization: Bearer ${esc(key)}`,
      '',
      `${esc(webhook.url)}?key=${esc(encodeURIComponent(key))}`
    ].join('\n');
    const { node, close } = dialog(
      '保存你的 Webhook key',
      /* HTML */ `
        <div class="notice">
          <strong>明文只显示这一次。</strong>
          <p>关闭后无法再次查看。请立即安全保存；遗失时需要轮换 key。</p>
        </div>
        <div class="secret">
          <code id="secret-value">${esc(key)}</code>
          <button class="button small" id="copy-key">复制 key</button>
        </div>
        <h3>三种传 key 的方式</h3>
        <p>任选一种。Header 更适合避免 key 出现在 URL 记录中。</p>
        <pre>${keyUsage}</pre>
        <h3>curl 示例</h3>
        <pre>${esc(curl)}</pre>
        <div class="form-footer">
          <button class="button primary" id="saved-key">
            已安全保存，关闭
          </button>
        </div>
      `,
      {
        onClose: () => {
          key = '';
        }
      }
    );
    $('#copy-key', node).onclick = () => copy(key);
    $('#saved-key', node).onclick = close;
  }
  // Channel filters and identifier editing
  const modeNames = { all: '全部事件', include: '仅包含', exclude: '排除名单' };
  function renderChannelRow(channel) {
    return /* HTML */ `
      <article class="resource" data-row-key="${esc(channel.id)}">
        <div class="resource-head">
          <div>
            <div class="resource-heading">
              <h3 class="mono">${esc(channel.name)}</h3>
              <span class="badge green">
                <span class="dot"></span>
                ${channel.active_streams} 在线 stream
              </span>
            </div>
            ${
              channel.description
                ? /* HTML */ `
                    <p>${esc(channel.description)}</p>
                  `
                : ''
            }
          </div>
          <div class="actions">
            <button
              class="button quiet small"
              data-channel-edit="${esc(channel.id)}"
            >
              编辑
            </button>
            <button
              class="button quiet small danger"
              data-channel-delete="${esc(channel.id)}"
            >
              删除
            </button>
          </div>
        </div>
        <div class="resource-meta">
          <span>${modeNames[channel.mode] || esc(channel.mode)}</span>
          <span>${channel.subscription_count} 个 webhook 订阅</span>
        </div>
        ${
          channel.identifiers?.length
            ? /* HTML */ `
                <div class="chips" style="margin:12px 0 0">
                  ${channel.identifiers
                    .map(
                      (identifier) => /* HTML */ `
                        <span
                          class="badge ${identifier.startsWith(':') ? 'purple' : ''}"
                        >
                          ${esc(identifier)}
                        </span>
                      `
                    )
                    .join('')}
                </div>
              `
            : ''
        }
      </article>
    `;
  }

  function renderChannels(host, identityId, items) {
    resourceMarkup(host, /* HTML */ `
      <div class="section-caption">
        <span>${items.length} 个投递通道</span>
        <button class="button primary" id="create-channel">
          ＋ 新建 Channel
        </button>
      </div>
      <section class="list" aria-label="Channels">
        ${
          items.length
            ? items.map(renderChannelRow).join('')
            : renderEmptyState(
                '还没有 Channel',
                '用 Channel 定义 Agent 接收哪些事件；修改后会立即作用于在线订阅。'
              )
        }
      </section>
      <p class="bottom-note">平台广播始终投递，不受 Channel 过滤规则影响。</p>
    `);
    $('#create-channel', host).onclick = () => openChannelForm(identityId);
    $$('[data-channel-edit]', host).forEach(
      (button) =>
        (button.onclick = () =>
          openChannelForm(
            identityId,
            items.find(
              (candidateChannel) =>
                candidateChannel.id === button.dataset.channelEdit
            )
          ))
    );
    $$('[data-channel-delete]', host).forEach(
      (button) =>
        (button.onclick = () => {
          const channel = items.find(
            (candidateChannel) =>
              candidateChannel.id === button.dataset.channelDelete
          );
          confirm({
            title: '删除 Channel？',
            message: `「${channel.name}」的在线订阅将收到 terminated 并断开。`,
            action: async () => {
              await api(
                identityAPIPath(identityId) +
                  '/channels/' +
                  encodeURIComponent(channel.id),
                { method: 'DELETE' }
              );
              toast('Channel 已删除');
              refreshTab(identityId, 'channels');
            }
          });
        })
    );
  }

  function openChannelForm(identityId, channel) {
    let identifiers = [...(channel?.identifiers || [])];
    const node = formDialog(
      channel ? '编辑 Channel' : '新建 Channel',
      renderField('Channel 名称', 'name', channel?.name, {
        required: true,
        readonly: !!channel,
        pattern: normalPattern,
        maxlength: 64,
        placeholder: 'ci',
        hint: channel
          ? '创建后不可修改。'
          : '小写字母、数字和连接用的短横线，最长 64 字符。'
      }) +
        renderDescriptionField(channel?.description) +
        /* HTML */ `
          <fieldset>
            <legend>事件过滤</legend>
            <div class="segmented">
              ${Object.entries(modeNames)
                .map(
                  ([value, label]) => /* HTML */ `
                    <label>
                      <input
                        type="radio"
                        name="mode"
                        value="${value}"
                        ${(channel?.mode || 'all') === value ? 'checked' : ''}
                      />
                      <span>
                        ${label}
                        <br />
                        <code>${value}</code>
                      </span>
                    </label>
                  `
                )
                .join('')}
            </div>
            <p id="mode-help" class="hint" style="margin-top:9px"></p>
          </fieldset>
          <div id="identifier-editor">
            <div class="field">
              <label for="identifier-input">identifier 名单</label>
              <div id="identifier-chips" class="chips"></div>
              <div class="inline-input">
                <input
                  id="identifier-input"
                  placeholder="github-push 或 :system"
                  aria-describedby="identifier-help"
                />
                <button type="button" id="add-identifier" class="button">
                  添加
                </button>
              </div>
              <span class="hint" id="identifier-help">
                支持普通 identifier 和 :system、:xxx 等平台保留标识。
              </span>
              <p class="error" id="identifier-error" role="alert" hidden></p>
            </div>
          </div>
        `,
      async (formData, close) => {
        const mode = String(formData.get('mode'));
        if (mode !== 'all' && $('#identifier-input', node).value.trim()) {
          if (!addIdentifier()) {
            throw new Error('请先修正 identifier。');
          }
        }
        const body = {
          description: String(formData.get('description')).trim(),
          mode,
          identifiers: mode === 'all' ? [] : identifiers
        };
        if (!channel) {
          body.name = String(formData.get('name'));
        }
        await api(
          identityAPIPath(identityId) +
            '/channels' +
            (channel ? '/' + encodeURIComponent(channel.id) : ''),
          { method: channel ? 'PATCH' : 'POST', body }
        );
        close();
        toast('Channel 已保存，过滤规则立即生效');
        refreshTab(identityId, 'channels');
      }
    );
    function drawChips() {
      const host = $('#identifier-chips', node);
      host.innerHTML = identifiers
        .map(
          (value, index) => /* HTML */ `
            <span class="chip">
              ${esc(value)}
              <button
                type="button"
                data-remove="${index}"
                aria-label="移除 ${esc(value)}"
              >
                ×
              </button>
            </span>
          `
        )
        .join('');
      $$('[data-remove]', host).forEach(
        (button) =>
          (button.onclick = () => {
            identifiers.splice(Number(button.dataset.remove), 1);
            drawChips();
            $('#identifier-input', node).focus({ preventScroll: true });
          })
      );
    }
    function addIdentifier() {
      const input = $('#identifier-input', node);
      const value = input.value.trim();
      const error = $('#identifier-error', node);
      error.hidden = true;
      if (!value) {
        return true;
      }
      if (
        !(value.startsWith(':')
          ? new RegExp('^' + reservedPattern + '$').test(value)
          : value.length <= 64 &&
            new RegExp('^' + normalPattern + '$').test(value))
      ) {
        error.textContent =
          '请输入合法的 identifier，例如 github-push 或 :system。';
        error.hidden = false;
        return false;
      }
      if (!identifiers.includes(value)) {
        identifiers.push(value);
      }
      input.value = '';
      drawChips();
      input.focus({ preventScroll: true });
      return true;
    }
    $('#add-identifier', node).onclick = addIdentifier;
    $('#identifier-input', node).onkeydown = (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        addIdentifier();
      }
    };
    function updateMode() {
      const mode = $('input[name="mode"]:checked', node).value;
      $('#identifier-editor', node).hidden = mode === 'all';
      $('#mode-help', node).textContent = {
        all: '接收这个 Identity 的全部事件。',
        include: '只接收名单中的事件；名单为空时仅接收平台广播。',
        exclude: '接收名单以外的事件。'
      }[mode];
    }
    $$('input[name="mode"]', node).forEach(
      (modeInput) => (modeInput.onchange = updateMode)
    );
    drawChips();
    updateMode();
  }
  // OAuth authorizations
  function renderAuthorizationRow(authorization) {
    const isCIMD = authorization.registration === 'cimd';
    const source = isCIMD
      ? /* HTML */ `
          <p class="authorization-source">
            来源 <strong class="mono break">${esc(authorization.metadata_host)}</strong>
          </p>
        `
      : '';
    return /* HTML */ `
      <article class="resource" data-row-key="${esc(authorization.id)}">
        <div class="resource-head">
          <div>
            <div class="resource-heading">
              <h3>${esc(authorization.client_name || '未命名客户端')}</h3>
              <span class="badge">${isCIMD ? 'CIMD' : '动态注册'}</span>
            </div>
            ${source}
            <p class="mono">${esc(authorization.redirect_host)}</p>
          </div>
          <button
            class="button danger small"
            data-auth-delete="${esc(authorization.id)}"
          >
            撤销授权
          </button>
        </div>
        <div class="resource-meta">
          <span>最近使用：${esc(date(authorization.last_used_at))}</span>
          <span>授权于 ${esc(date(authorization.created_at))}</span>
        </div>
        <details>
          <summary>客户端 ID</summary>
          <code class="break">${esc(authorization.client_id)}</code>
        </details>
      </article>
    `;
  }

  function renderAuthorizations(host, identityId, items) {
    resourceMarkup(host, /* HTML */ `
      <div class="section-caption">
        <span>${items.length} 条 OAuth 授权</span>
        <span>每条授权独立撤销</span>
      </div>
      <section class="list">
        ${
          items.length
            ? items.map(renderAuthorizationRow).join('')
            : renderEmptyState(
                '暂无授权客户端',
                '让 Agent 通过 MCP OAuth 接入，在授权页选择这个 Identity。'
              )
        }
      </section>
    `);
    $$('[data-auth-delete]', host).forEach(
      (button) =>
        (button.onclick = () => {
          const authorization = items.find(
            (candidateAuthorization) =>
              candidateAuthorization.id === button.dataset.authDelete
          );
          confirm({
            title: '撤销客户端授权？',
            message:
              `「${authorization.client_name || authorization.client_id}」` +
              '的 access token 和 refresh token 会立即失效。',
            label: '撤销授权',
            action: async () => {
              await api(
                identityAPIPath(identityId) +
                  '/authorizations/' +
                  encodeURIComponent(authorization.id),
                { method: 'DELETE' }
              );
              toast('授权已撤销');
              refreshTab(identityId, 'authorizations');
            }
          });
        })
    );
  }
  // Webhook delivery subscriptions
  function renderSubscriptionRow(subscription, names) {
    const statusClass =
      subscription.status === 'active'
        ? 'green'
        : subscription.status === 'failing'
          ? 'red'
          : '';

    return /* HTML */ `
      <article class="resource" data-row-key="${esc(subscription.id)}">
        <div class="resource-head">
          <div class="resource-heading">
            <h3 class="mono">${esc(subscription.channel)}</h3>
            <span
              class="badge ${statusClass}"
            >
              ${names[subscription.status] || esc(subscription.status)}
            </span>
          </div>
          <button
            class="button danger small"
            data-sub-delete="${esc(subscription.id)}"
          >
            删除订阅
          </button>
        </div>
        <p class="mono break">${esc(subscription.url)}</p>
        <div class="resource-meta">
          <span>失败 ${subscription.failure_count} 次</span>
          <span>最后投递：${esc(date(subscription.last_delivery_at))}</span>
          <span>到期：${esc(date(subscription.expires_at))}</span>
        </div>
        ${
          subscription.last_error
            ? /* HTML */ `
                <p class="error">最后错误：${esc(subscription.last_error)}</p>
              `
            : ''
        }
      </article>
    `;
  }

  function renderSubscriptions(host, identityId, items) {
    const names = {
      active: '正常投递',
      failing: '投递失败',
      expired: '已过期',
      terminated: '已终止'
    };
    resourceMarkup(host, /* HTML */ `
      <div class="section-caption">
        <span>${items.length} 个 webhook 投递订阅</span>
        <span>由 Agent 通过 MCP 创建</span>
      </div>
      <section class="list">
        ${
          items.length
            ? items
                .map((subscription) =>
                  renderSubscriptionRow(subscription, names)
                )
                .join('')
            : renderEmptyState(
                '暂无 webhook 投递订阅',
                'Agent 使用 webhook 模式订阅 Channel 后，可以在这里查看投递状态和错误。'
              )
        }
      </section>
    `);
    $$('[data-sub-delete]', host).forEach(
      (button) =>
        (button.onclick = () =>
          confirm({
            title: '删除事件订阅？',
            message:
              '删除后会立即停止向该回调地址投递事件，Agent 需要重新订阅。',
            action: async () => {
              await api(
                identityAPIPath(identityId) +
                  '/subscriptions/' +
                  encodeURIComponent(button.dataset.subDelete),
                { method: 'DELETE' }
              );
              toast('订阅已删除');
              refreshTab(identityId, 'subscriptions');
            }
          }))
    );
  }
  // Event history, live stream, and payload details
  function renderEventRow(eventRecord) {
    const summary =
      eventRecord.kind === 'system'
        ? eventRecord.data?.title || eventRecord.data?.message || '平台广播'
        : eventRecord.data?.webhook?.name ||
          eventRecord.data?.request?.method ||
          'Webhook 请求';
    const identityLabel =
      eventRecord.identity_id === null
        ? '全部 Agent'
        : esc(eventRecord.identity_name || eventRecord.identity_id);

    const time = new Date(eventRecord.received_at);
    const encoding = eventRecord.data?.request?.body_encoding || 'none';
    return /* HTML */ `
      <button
        type="button"
        data-row-key="${esc(eventRecord.seq)}"
        class="event-row ${eventRecord.kind === 'system' ? 'system' : ''}"
        data-event="${esc(eventRecord.id)}"
        aria-label="查看事件 ${esc(eventRecord.identifier)} #${eventRecord.seq}"
      >
        <time
          datetime="${esc(eventRecord.received_at)}"
          title="${esc(date(eventRecord.received_at))}"
        >
          ${esc(time.toLocaleTimeString('zh-CN', { hour12: false }))}
          <span class="event-summary">
            ${esc(time.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }))}
            · #${eventRecord.seq}
          </span>
        </time>
        <span>
          <span class="event-identifier">${esc(eventRecord.identifier)}</span>
          <span class="event-summary">
            ${esc(summary)}
          </span>
        </span>
        <span class="event-owner">
          ${identityLabel}
        </span>
        <span class="event-type">
          <span class="badge ${eventRecord.kind === 'system' ? 'purple' : ''}">
            ${eventRecord.kind === 'system' ? '平台广播' : esc(encoding.toUpperCase())}
          </span>
        </span>
      </button>
    `;
  }

  function renderEventColumnLabels() {
    return /* HTML */ `
      <div class="event-labels" aria-hidden="true">
        <span>接收时间</span>
        <span>事件 identifier</span>
        <span>Identity</span>
        <span>类型 / 正文</span>
      </div>
    `;
  }

  function renderEvents(params) {
    if (currentView?.page !== 'events') {
      currentView = { page: 'events' };
      main.innerHTML =
        renderPageHeader(
          '事件流',
          '查看接收到的原始请求与平台广播，新事件会实时进入列表。'
        ) +
        /* HTML */ `
          <div class="filters">
            <div id="identity-filter-region">
              <button
                id="identity-filter"
                class="button"
                aria-label="按 Identity 过滤"
                aria-haspopup="menu"
                aria-expanded="false"
              >
                全部身份
              </button>
            </div>
            <form id="event-filter">
              <input
                name="identifier"
                placeholder="按 identifier 过滤"
                aria-label="按 identifier 过滤"
              />
              <button class="button" type="submit">筛选</button>
              <button
                class="button quiet"
                type="button"
                id="clear-event-filter"
                hidden
              >
                清除
              </button>
            </form>
            <span class="stream-state" id="stream-state" role="status">
              <span class="dot"></span>正在连接
            </span>
          </div>
          <div class="section-caption">
            <span id="event-count" role="status"></span>
            <button class="button quiet small" id="refresh-events">刷新</button>
          </div>
          <section
            class="list data-region"
            id="event-list"
            aria-label="事件列表"
          >
            <div id="event-rows"></div>
          </section>
          <div id="event-pagination" class="load-more"></div>
        `;
      eventsState = createEventsState();
    }
    eventsState.setFilters(params);
  }

  function createEventsState() {
    const list = $('#event-list');
    const rows = $('#event-rows');
    const pagination = $('#event-pagination');
    const state = {
      selected: '',
      identifier: '',
      items: [],
      next: null,
      loaded: false,
      pending: [],
      key: null,
      refreshing: false
    };
    const active = () => eventsState === state && list.isConnected;
    function options() {
      return [
        { value: '', label: '全部身份' },
        { value: '_broadcast', label: '仅平台广播' },
        ...identities.map((identity) => ({
          value: identity.id,
          label: identity.name
        }))
      ];
    }
    state.updateIdentityFilter = () => {
      $('#identity-filter').textContent =
        (options().find((option) => option.value === state.selected)?.label ||
          '未知身份') + ' ⌄';
    };
    state.refreshIdentities = () =>
      loadRegion(
        $('#identity-filter-region'),
        'Identity 选项',
        () => requestIdentities(),
        () => {},
        identitiesLoaded,
        { background: identitiesLoaded }
      );
    function filterRoute(selected, identifier) {
      const query = new URLSearchParams();
      if (selected) {
        query.set('identity_id', selected);
      }
      if (identifier) {
        query.set('identifier', identifier);
      }
      navigate('#/events' + (query.size ? '?' + query : ''));
    }
    $('#identity-filter').onclick = (event) =>
      menu(event.currentTarget, options(), state.selected, (value) =>
        filterRoute(value, state.identifier)
      );
    $('#event-filter').onsubmit = (event) => {
      event.preventDefault();
      filterRoute(
        state.selected,
        String(new FormData(event.currentTarget).get('identifier')).trim()
      );
    };
    $('#clear-event-filter').onclick = () => filterRoute(state.selected, '');
    $('#refresh-events').onclick = () => refresh();
    function matches(eventRecord) {
      return (
        (!state.selected ||
          (state.selected === '_broadcast'
            ? eventRecord.identity_id === null
            : eventRecord.identity_id === state.selected)) &&
        (!state.identifier || eventRecord.identifier === state.identifier)
      );
    }
    function merge(items) {
      const records = new Map(
        state.items.map((eventRecord) => [eventRecord.seq, eventRecord])
      );
      items
        .filter(matches)
        .forEach((eventRecord) => records.set(eventRecord.seq, eventRecord));
      state.items = [...records.values()].sort(
        (left, right) => right.seq - left.seq
      );
    }
    function drawRows() {
      if (!active()) {
        return;
      }
      $('#event-count').textContent =
        `已加载 ${state.items.length} 条事件 · 按接收时间倒序`;
      patchRows(
        rows,
        state.items.length
          ? renderEventColumnLabels() + state.items.map(renderEventRow).join('')
          : renderEmptyState(
              '没有匹配的事件',
              '调整过滤条件，或向 Webhook 发送一次请求。新的事件会自动出现在这里。'
            )
      );
      $$('[data-event]', rows).forEach((button) => {
        button.onclick = () =>
          eventDetail(
            state.items.find((record) => record.id === button.dataset.event)
          );
      });
    }
    function drawPagination() {
      if (state.next !== null) {
        if (!$('#load-more')) {
          pagination.innerHTML =
            '<button class="button" id="load-more">加载更多历史事件</button>';
        }
        $('#load-more').disabled = state.refreshing;
        $('#load-more').onclick = loadMore;
      } else {
        pagination.innerHTML =
          state.items.length && !state.refreshing
            ? '<span class="hint">已显示全部历史事件</span>'
            : '';
      }
    }
    function query(before) {
      const params = new URLSearchParams({ limit: '50' });
      if (state.selected) {
        params.set('identity_id', state.selected);
      }
      if (state.identifier) {
        params.set('identifier', state.identifier);
      }
      if (before !== undefined) {
        params.set('before', String(before));
      }
      return '/api/events?' + params;
    }
    async function loadMore() {
      if (regions.has(pagination) || state.refreshing || state.next === null) {
        return;
      }
      const url = query(state.next);
      $('#load-more').disabled = true;
      await loadRegion(
        pagination,
        '历史事件',
        (signal) => api(url, { signal }),
        (data) => {
          merge(data.events || []);
          state.next = data.next_before ?? null;
          drawRows();
          drawPagination();
        },
        true,
        { retry: loadMore }
      );
      if (active()) {
        const button = $('#load-more');
        if (button) {
          button.disabled = state.refreshing;
        }
      }
    }
    function refresh() {
      cancelRegion(pagination);
      pagination.querySelector('.region-error')?.remove();
      state.refreshing = true;
      state.pending = [];
      drawPagination();
      const url = query();
      return loadRegion(
        list,
        '事件',
        async (signal) => {
          try {
            return await api(url, { signal });
          } catch (error) {
            if (!signal.aborted && active()) {
              if (!state.loaded) {
                state.items = [];
              }
              state.loaded = true;
              state.refreshing = false;
              merge(state.pending);
              state.pending = [];
              if (state.items.length) {
                drawRows();
              }
              $('#event-count').textContent = '读取事件失败，可在列表中重试';
              drawPagination();
            }
            throw error;
          }
        },
        (data) => {
          state.items = [];
          merge([...(data.events || []), ...state.pending]);
          state.pending = [];
          state.loaded = true;
          state.refreshing = false;
          state.next = data.next_before ?? null;
          drawRows();
          drawPagination();
        },
        rows.children.length > 0,
        { retry: refresh }
      );
    }
    state.setFilters = (params) => {
      const selected = params.get('identity_id') || '';
      const identifier = params.get('identifier') || '';
      const key = JSON.stringify([selected, identifier]);
      if (key !== state.key) {
        state.key = key;
        state.selected = selected;
        state.identifier = identifier;
        state.loaded = false;
        state.next = null;
        $('#event-filter input').value = identifier;
        $('#clear-event-filter').hidden = !identifier;
        state.updateIdentityFilter();
      }
      refresh();
    };
    eventSource = new EventSource('/api/events/stream');
    const stream = eventSource;
    let checking = false;
    stream.onopen = () => {
      if (active()) {
        $('#stream-state').dataset.connected = 'true';
        $('#stream-state').innerHTML = '<span class="dot"></span>实时连接';
      }
    };
    stream.addEventListener('event', (message) => {
      if (!active()) {
        return;
      }
      try {
        const eventRecord = JSON.parse(message.data);
        if (!matches(eventRecord)) {
          return;
        }
        if (state.refreshing) {
          state.pending.push(eventRecord);
        }
        if (state.loaded || rows.children.length) {
          merge([eventRecord]);
          drawRows();
        }
      } catch {
        toast('收到无法解析的事件，请刷新重试。');
      }
    });
    stream.onerror = async () => {
      if (!active()) {
        return;
      }
      $('#stream-state').dataset.connected = 'false';
      $('#stream-state').textContent = '连接中断，自动重连…';
      if (checking) {
        return;
      }
      checking = true;
      try {
        await requestIdentities();
      } catch (error) {
        if (error.status === 401) {
          stream.close();
        }
      } finally {
        checking = false;
      }
    };
    return state;
  }

  function eventDetail(eventRecord) {
    const identityLabel =
      eventRecord.identity_id === null
        ? '平台广播 → 全部 Agent'
        : esc(eventRecord.identity_name || eventRecord.identity_id);
    const data = eventRecord.data || {};
    const request = data.request;
    let body = '';
    if (eventRecord.kind === 'system') {
      body = /* HTML */ `
        <h3>${esc(data.title || '平台广播')}</h3>
        <pre>${esc(data.message || '')}</pre>
        <p class="hint" style="margin-top:12px">
          此事件绕过 Channel 过滤，投递给所有 Agent。
        </p>
      `;
    } else if (!request || request.body_encoding === 'none') {
      body = '<div class="notice">这个请求没有正文。</div>';
    } else if (request.body_encoding === 'json') {
      body = /* HTML */ `
        <pre aria-label="JSON 正文">${json(request.body)}</pre>
      `;
    } else if (request.body_encoding === 'text') {
      body = /* HTML */ `
        <pre aria-label="文本正文">${esc(request.body)}</pre>
      `;
    } else if (request.body_encoding === 'base64') {
      let preview;
      let explanation;
      try {
        const binary = atob(request.body);
        const bytes = Uint8Array.from(binary, (character) =>
          character.charCodeAt(0)
        );
        try {
          preview = new TextDecoder('utf-8', { fatal: true }).decode(
            bytes.slice(0, 4096)
          );
          explanation = 'UTF-8 解码预览';
        } catch {
          preview = [...bytes.slice(0, 4096)]
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join(' ')
            .replace(/(.{48})/g, '$1\n');
          explanation = '二进制内容 · 十六进制解码预览';
        }
        if (bytes.length > 4096) {
          explanation += '（前 4096 字节）';
        }
      } catch {
        preview = '无法解码：内容不是有效的 Base64。';
        explanation = '解码失败';
      }
      body = /* HTML */ `
        <p class="hint" style="margin-bottom:8px">${explanation}</p>
        <pre aria-label="Base64 解码预览">${esc(preview)}</pre>
        <details>
          <summary>原始 Base64</summary>
          <pre>${esc(request.body)}</pre>
        </details>
      `;
    } else {
      body = /* HTML */ `
        <pre>${esc(request.body)}</pre>
      `;
    }
    const { node } = dialog(
      eventRecord.kind === 'system' ? '平台广播详情' : 'Webhook 事件详情',
      /* HTML */ `
        <dl class="event-details">
          <dt>事件</dt>
          <dd class="mono">${esc(eventRecord.id)} · #${eventRecord.seq}</dd>
          <dt>identifier</dt>
          <dd>
            <span
              class="badge ${eventRecord.kind === 'system' ? 'purple' : ''}"
            >
              ${esc(eventRecord.identifier)}
            </span>
          </dd>
          <dt>Identity</dt>
          <dd>
            ${identityLabel}
          </dd>
          <dt>接收时间</dt>
          <dd>${esc(date(eventRecord.received_at))}</dd>
          ${
            request
              ? /* HTML */ `
                  <dt>请求</dt>
                  <dd class="mono">
                    ${esc(request.method)} ·
                    ${esc(request.content_type || '未提供 Content-Type')}
                  </dd>
                `
              : ''
          }
        </dl>
        <div class="payload-label">
          <h3>正文</h3>
          <span class="badge">
            ${eventRecord.kind === 'system' ? 'system' : esc(request?.body_encoding || 'none')}
          </span>
        </div>
        ${body}${
          request
            ? /* HTML */ `
                <h3>请求 Headers</h3>
                <pre aria-label="请求 Headers">${json(request.headers || {})}</pre>
                <details>
                  <summary>Query 参数</summary>
                  <pre>${json(request.query || {})}</pre>
                </details>
              `
            : ''
        }
        <details>
          <summary>完整事件 JSON</summary>
          <pre aria-label="完整事件 JSON">${json(eventRecord)}</pre>
        </details>
        <div class="form-footer">
          <button class="button" id="copy-event">复制完整 JSON</button>
        </div>
      `,
      { wide: true }
    );
    $('#copy-event', node).onclick = () =>
      copy(JSON.stringify(eventRecord, null, 2));
  }
  // Platform broadcasts
  function renderBroadcast() {
    const identifierField = renderField(
      '保留 identifier',
      'identifier',
      ':system',
      {
        required: true,
        pattern: reservedPattern,
        hint: '以冒号开头的平台保留标识，例如 :system。'
      }
    );
    const titleField = renderField('标题（可选）', 'title', '', {
      placeholder: '例如：维护通知'
    });
    main.innerHTML =
      renderPageHeader('平台广播', '向所有 Agent 发送一条系统消息。') +
      /* HTML */ `
        <div class="broadcast-layout">
          <form class="broadcast-form" id="broadcast-form">
            ${identifierField}${titleField}
            <div class="field">
              <label for="broadcast-message">广播正文</label>
              <textarea
                name="message"
                id="broadcast-message"
                rows="7"
                placeholder="输入要发送给所有 Agent 的消息…"
                required
              ></textarea>
            </div>
            <div class="notice">
              <strong>所有 Agent 都会收到</strong>
              <p>
                广播会绕过 Channel 的 include / exclude 过滤规则，投递给所有
                Agent 的在线订阅。
              </p>
            </div>
            ${formErrorMarkup}
            <div class="form-footer">
              <button class="button primary" type="submit">
                发送平台广播 ↗
              </button>
            </div>
            <div id="broadcast-result" role="status"></div>
          </form>
          <aside class="broadcast-aside">
            <h3>一条消息，所有接入。</h3>
            <p>适合发送平台维护、重要变更或需要 Agent 注意的系统通知。</p>
            <div class="flow-step">
              <span class="badge purple">:system</span>
              <span>→</span>
              <span>所有 Identity</span>
            </div>
            <p>消息会作为系统事件写入事件流，标记为「平台广播」。</p>
            <a href="#/events?identity_id=_broadcast" class="button">
              查看广播记录 ↗
            </a>
          </aside>
        </div>
      `;
    bindForm($('#broadcast-form'), async (formData) => {
      const message = String(formData.get('message')).trim();
      if (!message) {
        throw new Error('请输入广播正文。');
      }
      const result = await api('/api/broadcast', {
        method: 'POST',
        body: {
          identifier: String(formData.get('identifier')),
          title: String(formData.get('title')).trim(),
          message
        }
      });
      $('#broadcast-message').value = '';
      $('#field-title').value = '';
      $('#broadcast-result').innerHTML = /* HTML */ `
        <div class="notice" style="margin-top:18px">
          广播已发送。
          <br />
          <code>${esc(result.event_id)}</code>
          <br />
          <a class="button quiet small" href="#/events?identity_id=_broadcast">
            在事件流查看 ↗
          </a>
        </div>
      `;
      toast('平台广播已发送');
    });
  }
  // Hash routing and application startup
  function renderPage() {
    const fragment = location.hash.slice(1) || '/identities';
    const [pathname, search = ''] = fragment.split('?');
    const parts = pathname.split('/').filter(Boolean);
    const page = parts[0] || 'identities';
    const identityId =
      page === 'identities' && parts[1] ? decodeURIComponent(parts[1]) : null;
    const sameShell =
      currentView?.page === page &&
      (currentView.identityId || null) === identityId;
    if (!sameShell) {
      regions.forEach((request, host) => cancelRegion(host));
      eventSource?.close();
      eventSource = null;
      eventsState = null;
      currentView = null;
    }
    $$('.sidebar [data-nav]').forEach((link) => {
      if (link.dataset.nav === page) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    });
    if (identityId) {
      renderIdentity(identityId, parts[2] || 'webhooks');
    } else if (page === 'identities') {
      if (!sameShell) {
        currentView = { page };
        renderIdentities();
      }
    } else if (page === 'events') {
      renderEvents(new URLSearchParams(search));
    } else if (page === 'broadcast') {
      if (!sameShell) {
        currentView = { page };
        renderBroadcast();
      }
    } else if (!sameShell) {
      currentView = { page };
      main.innerHTML = renderEmptyState(
        '页面不存在',
        '使用左侧导航继续管理工作空间。',
        '<a class="button" href="#/identities">返回身份列表</a>'
      );
    }
    if (!sameShell) {
      refreshIdentities();
    }
  }
  api('/api/meta')
    .then((meta) => {
      $('#version').textContent = meta.version;
      const button = $('#mcp-copy');
      button.disabled = false;
      button.title = meta.mcp_url;
      button.onclick = () => copy(meta.mcp_url);
    })
    .catch((requestError) => {
      if (requestError.status !== 401) {
        $('#version').textContent = '版本未知';
        toast('无法读取服务信息：' + requestError.message);
      }
    });
  $('#logout').onclick = async () => {
    const button = $('#logout');
    button.disabled = true;
    try {
      await api('/api/logout', { method: 'POST' });
      location.assign('/login');
    } catch (requestError) {
      if (requestError.status !== 401) {
        toast(requestError.message);
      }
      button.disabled = false;
    }
  };
  let lastRoute = location.href;
  const routeChanged = () => {
    if (lastRoute === location.href) {
      return;
    }
    lastRoute = location.href;
    renderPage();
  };
  window.addEventListener('hashchange', routeChanged);
  window.addEventListener('popstate', routeChanged);
  window.addEventListener('pagehide', () => eventSource?.close());
  renderPage();
})();
