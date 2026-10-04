'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const defaults = {
    preset: 'ru-direct',
    capture: 'local',
    dns: 'system',
    ru_ip: false,
    auto_reconnect: true,
    direct: '',
    proxy: '',
    block: ''
  };
  const state = {
    ready: false,
    phase: 'idle',
    active: false,
    settings: {
      ...defaults
    },
    profiles: [],
    selected: null,
    environment: {},
    rules: {},
    panel: null,
    events: [],
    samples: [],
    sites: null,
    analytics: null,
    transient: null,
    checking: false,
    latency: null
  };
  const titles = {
    profiles: 'Профили',
    routing: 'Маршруты',
    settings: 'Настройки',
    activity: 'Активность'
  };
  // Drafts live only in renderer memory, never in localStorage or diagnostics.
  const drafts = new Map();
  let returnFocus = null,
    toastTimer, editingId = null,
    editorBusy = false,
    rulesBusy = false,
    pendingSettings = null,
    savePanel = null,
    pendingDeletion = null,
    controlsLocked = null,
    activityTab = 'connection',
    homeProfilesKey = '',
    homeSitesKey = '',
    homeExtrasKey = '',
    chartFrame = 0,
    chartDirty = false;
  const bridge = window.chrome?.webview;

  function send(action, fields = {}) {
    if (bridge) bridge.postMessage({
      action,
      ...fields
    });
    else document.dispatchEvent(new CustomEvent('yukiwire-command', {
      detail: {
        action,
        ...fields
      }
    }));
  }

  function text(id, value) {
    const el = $(id);
    const next = String(value ?? '');
    // Telemetry must not repeatedly announce an unchanged live status.
    if (el && el.textContent !== next) el.textContent = next;
  }

  function bytes(n) {
    n = Math.max(0, Number(n) || 0);
    const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
    let u = 0;
    while (n >= 1024 && u < 4) {
      n /= 1024;
      u++;
    }
    return `${n.toLocaleString('ru-RU',{maximumFractionDigits:u?1:0})} ${units[u]}`;
  }

  function duration(n) {
    return [Math.floor(n / 3600), Math.floor(n / 60) % 60, Math.floor(n) % 60].map(x => String(x)
      .padStart(2, '0')).join(':');
  }

  function notice(message, error = false, persistent = false) {
    clearTimeout(toastTimer);
    text('toast-message', message);
    $('toast').classList.toggle('error', error);
    $('toast-icon').querySelector('use').setAttribute('href', error ? '#i-info' : '#i-check');
    $('toast').hidden = false;
    if (!persistent) toastTimer = setTimeout(() => $('toast').hidden = true, error ? 14000 : 7000);
  }

  function privateUiGet(key, fallback) {
    try {
      return JSON.parse(localStorage.getItem(key)) ?? fallback;
    } catch {
      return fallback;
    }
  }

  function privateUiSet(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* UI preferences are optional. */ }
  }
  document.body.classList.toggle('reduce-motion', privateUiGet('reduce-motion', false));
  let theme = privateUiGet('theme', 'dark');
  const systemTheme = matchMedia('(prefers-color-scheme: dark)');
  function applyTheme(value = theme) {
    theme = ['dark', 'light', 'system'].includes(value) ? value : 'dark';
    const dark = theme === 'dark' || (theme === 'system' && systemTheme.matches);
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    $('theme-toggle').setAttribute('aria-label', dark ? 'Включить светлую тему' : 'Включить тёмную тему');
    $('theme-toggle').querySelector('use').setAttribute('href', dark ? '#i-sun' : '#i-moon');
    if ($('theme-select')) $('theme-select').value = theme;
    privateUiSet('theme', theme);
  }
  applyTheme();
  systemTheme.addEventListener('change', () => { if (theme === 'system') applyTheme(); });

  function selected() {
    return state.transient || state.profiles.find(p => p.id === state.selected);
  }

  function locked() {
    return state.active || ['connecting', 'stopping', 'reconnecting'].includes(state.phase);
  }

  function conflict() {
    return state.environment.other_proxy || state.environment.other_vpn || state.environment.check_failed;
  }

  function render() {
    const p = selected();
    text('profile-protocol', p ? String(p.protocol).toUpperCase() : 'Ссылка или JSON-конфигурация');
    const phase = state.phase;
    const busy = ['connecting', 'reconnecting', 'stopping'].includes(phase);
    const view = {
      idle: ['Отключено', p ? '' : 'Добавьте ссылку или файл конфигурации.'],
      connecting: ['Подключение…', ''],
      checking: ['Проверка соединения…', ''],
      connected: [state.settings.capture === 'local' ? 'Прокси готов' : 'Подключено',
        state.settings.capture === 'local' ? 'Прокси для отдельного браузера и настроенных приложений.' : ''],
      reconnecting: ['Переподключение…', ''],
      stopping: ['Отключение…', 'Восстанавливаем настройки сети.'],
      unverified: ['Не удалось проверить связь', 'Откройте «Активность», чтобы узнать причину.'],
      unavailable: ['Сервис недоступен', 'Перезапустите приложение.']
    }[phase] || ['Отключено', ''];
    text('connection-title', state.ready || phase === 'unavailable' ? view[0] : 'Запуск…');
    const hint = state.ready || phase === 'unavailable' ? view[1] : '';
    text('connection-hint', hint);
    $('connection-hint').hidden = !hint;
    $('environment-notice').hidden = !conflict();
    text('environment-notice', state.environment.check_failed ? 'Сеть не проверена' :
      state.environment.other_vpn ? 'Другой VPN' : 'Другой прокси');
    $('environment-notice').title = state.environment.check_failed ?
      'Не удалось проверить окружение Windows. Повторная проверка выполняется автоматически.' :
      'Обнаружен другой VPN или системный прокси. Доступен локальный режим. Проверка каждые 5 секунд.';
    const btn = $('connect-button');
    btn.disabled = !state.ready || phase === 'stopping' || !!pendingSettings || editorBusy;
    const blockedCapture = !locked() && p && conflict() && state.settings.capture !== 'local';
    btn.disabled ||= !!blockedCapture;
    btn.title = blockedCapture ? 'Выберите локальный режим или дождитесь завершения другого VPN и проверки сети.' : '';
    btn.classList.toggle('is-active', locked());
    btn.classList.toggle('busy', busy);
    btn.querySelector('span').textContent = phase === 'stopping' ? 'Отключаем…' : phase ===
      'connecting' ? 'Отменить' : locked() ? 'Отключить' : p ? 'Подключиться' : 'Добавить профиль';
    $('browser-button').hidden = !state.active || busy;
    $('check-button').disabled = !state.active || state.checking || busy;
    text('check-button', state.checking ? 'Проверяем…' : 'Проверить');
    text('profile-count', state.profiles.length);
    document.querySelector('.header-status').hidden = !state.panel;
    text('header-status', state.ready || phase === 'unavailable' ? ({connected: 'На связи', checking: 'Проверка связи', unverified: 'Нужна проверка', unavailable: 'Нет связи с сервисом'}[phase] || view[0]) : 'Запуск');
    $('header-dot').className = 'service-dot' + (phase === 'connected' ? ' active' : ['unverified', 'unavailable'].includes(phase) ? ' warning' : '');
    document.body.dataset.connection = phase;
    document.body.dataset.capture = state.settings.capture;
    $('locked-notice').hidden = !locked() || !['profiles', 'routing', 'settings'].includes(state.panel);
    $('unlock-settings').disabled = phase === 'stopping';
    renderHomeControls();
    renderHomeSites();
    renderHomeExtras();
    refreshControls();
  }

  function selectProfile(id) {
    if (locked() || editorBusy || pendingSettings || !state.ready) return;
    const profile = state.profiles.find(p => p.id === id);
    if (!profile) return;
    state.transient = null;
    state.selected = id;
    if (String(profile.protocol).toLowerCase().includes('json')) state.settings.preset = 'original';
    else if (state.settings.preset === 'original') state.settings.preset = 'ru-direct';
    render();
  }

  function renderHomeControls() {
    const profiles = $('home-profile');
    const key = JSON.stringify([state.profiles, state.transient?.name]);
    // Keep an open select and keyboard focus intact during status updates.
    if (key !== homeProfilesKey) {
      homeProfilesKey = key;
      profiles.replaceChildren();
      if (state.transient) profiles.add(new Option(state.transient.name, 'transient'));
      if (!state.profiles.length && !state.transient) profiles.add(new Option('Добавьте профиль', ''));
      for (const p of state.profiles) profiles.add(new Option(p.name, p.id));
    }
    profiles.value = state.transient ? 'transient' : state.selected || '';
    const disabled = locked() || !state.ready || !!pendingSettings || editorBusy;
    profiles.disabled = disabled || !state.profiles.length;
    $('home-add-profile').disabled = disabled || editorBusy;
    const settings = pendingSettings || state.settings;
    const capture = $('home-capture'), preset = $('home-preset');
    capture.value = settings.capture;
    preset.value = settings.preset;
    capture.disabled = preset.disabled = disabled;
    capture.querySelector('[value=system]').disabled = !!conflict();
    capture.querySelector('[value=tun]').disabled = !!conflict();
    preset.querySelector('[value=original]').disabled = !String(selected()?.protocol).toLowerCase().includes('json');
    text('home-save-status', pendingSettings ? 'Сохранение…' : '');
    capture.title = preset.title = locked() ? 'Отключитесь, чтобы изменить настройку' : '';
    document.querySelector('.home-endpoints').hidden = state.settings.capture !== 'local';
  }

  function saveHomeSetting(key, value) {
    if (locked() || !state.ready || pendingSettings) { renderHomeControls(); return; }
    if (state.settings[key] === value) return;
    savePanel = 'home';
    pendingSettings = {...state.settings, [key]: value};
    render();
    send('save_settings', {settings: pendingSettings});
  }

  function renderHomeSites() {
    const key = JSON.stringify([state.sites?.results, state.checking, state.active]);
    if (key === homeSitesKey) return;
    homeSitesKey = key;
    const box = $('home-sites');
    box.replaceChildren();
    const results = state.sites?.results || [];
    if (!results.length) {
      box.append(node('p', 'muted', state.checking ? 'Проверяем доступность сайтов…' : state.active ?
        'Проверьте доступность сайтов через текущее подключение.' : 'Подключитесь, чтобы проверить доступность сайтов.'));
      return;
    }
    if (!state.active) box.append(node('p', 'muted', 'Последняя проверка'));
    for (const result of results.slice(0, 3)) {
      const row = node('div', 'home-site');
      const status = result.accessible ? `${result.elapsed_ms} мс` : result.transport_ok ? `HTTP ${result.http_status}` : 'Нет связи';
      row.append(node('span', '', result.target), node('span', 'site-state' +
        (result.accessible ? '' : result.transport_ok ? ' denied' : ' failed'), status));
      box.append(row);
    }
    if (state.checking) box.append(node('p', 'muted', 'Обновляем результаты…'));
  }

  function renderHomeExtras() {
    const disabled = locked() || !state.ready || !!pendingSettings || editorBusy;
    const key = JSON.stringify([state.profiles, state.selected, disabled, state.events]);
    if (key === homeExtrasKey) return;
    homeExtrasKey = key;
    const profiles = $('home-profile-list');
    profiles.replaceChildren();
    for (const profile of state.profiles) {
      const row = node('button', 'home-profile-row');
      const caption = node('span');
      caption.append(node('strong', '', profile.name), node('small', '', String(profile.protocol).toUpperCase()));
      row.append(caption, icon('power'));
      row.setAttribute('aria-label', 'Подключить ' + profile.name);
      row.title = 'Подключить ' + profile.name;
      row.disabled = disabled;
      row.onclick = () => { selectProfile(profile.id); $('connect-button').click(); };
      profiles.append(row);
    }
    if (!state.profiles.length) profiles.append(node('p', 'muted', 'Добавьте профиль кнопкой + рядом с выбором сервера.'));
    const events = $('home-event-list');
    events.replaceChildren();
    for (const event of state.events.slice(0, 12)) {
      const row = node('li', event.severity || event.level || '');
      row.append(node('time', '', new Date(event.received).toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'})), node('span', '', event.message));
      events.append(row);
    }
    if (!state.events.length) events.append(node('li', '', 'События подключения появятся здесь.'));
  }

  function renderChart() {
    chartDirty = true;
    if (chartFrame) return;
    chartFrame = requestAnimationFrame(() => {
      chartFrame = 0;
      if (document.hidden || $('home-view').hidden) return;
      chartDirty = false;
      drawChart();
    });
  }

  function drawChart() {
    const samples = state.samples;
    const max = Math.max(1024, ...samples.flatMap(x => [x.down, x.up]));
    const y = n => 84 - Math.min(1, n / max) * 77;
    const offset = 60 - samples.length;
    const path = k => samples.map((s, i) =>
      `${i?'L':'M'}${((offset+i)/59*1000).toFixed(1)} ${y(s[k]).toFixed(1)}`).join(' ');
    const down = path('down');
    $('chart-down').setAttribute('d', down);
    $('chart-up').setAttribute('d', path('up'));
    $('chart-area').setAttribute('d', samples.length > 1 ?
      `${down}L1000 85L${(offset/59*1000).toFixed(1)} 85Z` : '');
    text('chart-max', samples.length ? bytes(max) + '/с' : '0 Б/с');
    $('chart-empty').hidden = !!samples.length;
  }

  function telemetry(data) {
    text('download-total', bytes(data.download_bytes));
    text('upload-total', bytes(data.upload_bytes));
    text('download-rate', bytes(data.download_bps) + '/с');
    text('upload-rate', bytes(data.upload_bps) + '/с');
    text('direct-total', 'Напрямую · ' + bytes(data.direct_bytes));
    text('uptime', duration(data.uptime || 0));
    text('reconnect-count', data.reconnects ? `Переподключений: ${data.reconnects}` : 'Без переподключений');
    state.samples.push({
      down: Number(data.download_bps) || 0,
      up: Number(data.upload_bps) || 0
    });
    if (state.samples.length > 60) state.samples.shift();
    renderChart();
  }

  function receive(data) {
    if (!data || typeof data.event !== 'string') return;
    switch (data.event) {
      case 'window_state': {
        const maximize = document.querySelector('[data-action="window_maximize"]');
        maximize.setAttribute('aria-label', data.maximized ? 'Восстановить размер' : 'Развернуть');
        maximize.textContent = data.maximized ? '❐' : '□';
        return;
      }
      case 'ready':
        state.ready = true;
        state.settings = {
          ...defaults,
          ...data.settings
        };
        state.profiles = data.profiles || [];
        state.selected = data.selected;
        state.environment = data.environment || {};
        state.rules = data.rules || {};
        if (data.warning) notice(data.warning, true, true);
        break;
      case 'profiles':
        state.profiles = data.profiles || [];
        state.selected = data.selected ?? (state.profiles.some(p => p.id === state.selected) ? state.selected : state.profiles[0]?.id ?? null);
        if (state.panel === 'profiles') renderProfiles();
        break;
      case 'environment':
        state.environment = data.environment || {};
        if (state.panel === 'settings') {
          const mode = $('settings-form').elements.namedItem('capture');
          mode.querySelector('[value=system]').disabled = !!conflict();
          mode.querySelector('[value=tun]').disabled = !!conflict();
        }
        if (!data.silent) notice(state.environment.check_failed ? 'Не удалось проверить окружение Windows.' :
          conflict() ? 'Другой VPN или прокси всё ещё включён.' :
          'Другой VPN и прокси не обнаружены.', !!state.environment.check_failed);
        break;
      case 'profile_detail':
        openPanel('profiles');
        openEditor(data.text, data.name, data.id);
        break;
      case 'saved':
        state.transient = null;
        editorBusy = false;
        state.selected = data.profile_id;
        editingId = null;
        drafts.delete('profiles');
        if (state.panel === 'profiles') {
          clearEditor();
          renderProfiles();
        }
        notice('Профиль сохранён.');
        break;
      case 'settings':
        state.settings = {
          ...defaults,
          ...data.settings
        };
        pendingSettings = null;
        drafts.delete(savePanel);
        if (state.panel === savePanel) {
          fillSettings($(savePanel === 'routing' ? 'routing-form' : 'settings-form'));
          if (savePanel === 'settings') $('settings-form').elements.namedItem('capture').dispatchEvent(new Event('change'));
          updateSaveState();
        }
        if (savePanel === 'home' && ['settings', 'routing'].includes(state.panel)) {
          fillSettings($(state.panel + '-form'));
          restoreDraft(state.panel);
        }
        if (savePanel !== 'home') notice(savePanel === 'routing' ? 'Маршруты сохранены.' : 'Настройки сохранены.');
        break;
      case 'starting':
        state.phase = 'connecting';
        break;
      case 'started':
        if (data.transient) state.transient = data.transient;
        state.phase = 'checking';
        state.active = true;
        state.checking = false;
        $('session-note').hidden = true;
        if (!data.reconnected) {
          state.samples = [];
          state.sites = null;
          state.latency = null;
          text('latency', '—');
          text('country', 'Страна выхода не проверена');
          telemetry({});
          state.samples = [];
          renderChart();
        }
        state.settings.capture = data.capture || state.settings.capture;
        break;
      case 'stopped':
        if (state.transient && !state.transient.text) state.transient = null;
        state.phase = 'idle';
        state.active = false;
        state.checking = false;
        text('download-rate', '0 Б/с');
        text('upload-rate', '0 Б/с');
        text('session-note', 'Последняя сессия');
        $('session-note').hidden = !state.samples.length;
        if (state.panel === 'activity') renderActivity();
        break;
      case 'probe_result':
        if (!state.active || state.phase === 'stopping') break;
        state.phase = 'connected';
        state.latency = data.elapsed_ms;
        text('latency', `${data.elapsed_ms} мс`);
        break;
      case 'reconnecting':
        state.phase = 'reconnecting';
        break;
      case 'core_exited':
        state.phase = 'unverified';
        break;
      case 'telemetry':
        telemetry(data);
        return;
      case 'analytics':
        state.analytics = data;
        if (state.panel === 'activity') renderAnalytics();
        break;
      case 'activity':
        state.events.unshift({
          ...data,
          received: Date.now()
        });
        state.events = state.events.slice(0, 100);
        if (state.panel === 'activity') renderActivity();
        break;
      case 'sites_checking':
        state.checking = true;
        if (state.panel === 'activity') renderActivity();
        break;
      case 'sites_result':
        state.checking = false;
        state.sites = data;
        const country = data.exit?.profile?.country;
        const chat = data.exit?.chatgpt_route?.country;
        text('country', country ? `Выход · ${country}` : 'Страна выхода неизвестна');
        if (state.panel === 'activity') renderActivity();
        if (country === 'RU' || chat === 'RU') notice(
          'Проверка показала выход в РФ. Проверьте сервер и маршруты.', true, true);
        break;
      case 'browser_opened':
        notice('Открыт браузер через Yukiwire.');
        break;
      case 'route_explanation':
        text('route-explanation',
          `${data.route} · ${data.reason}${data.definitive?'':' Это предварительная оценка.'}`);
        break;
      case 'rules_updating':
        rulesBusy = true;
        setRulesBusy();
        break;
      case 'rules_updated':
        rulesBusy = false;
        state.rules = data.rules || {};
        setRulesBusy();
        rulesVersion();
        notice('Списки проверены и обновлены.');
        break;
      case 'recovered':
        notice(data.conflict ? 'Есть конфликт восстановления. Текущие настройки сохранены.' : data
          .restored ? 'Собственные изменения восстановлены.' :
          'Незавершённых изменений Yukiwire нет.', !!data.conflict, true);
        break;
      case 'diagnostics_exported':
        notice('Отчёт сохранён: ' + data.path, false, true);
        break;
      case 'file_import':
        if (state.panel !== 'profiles') openPanel('profiles');
        openEditor(data.text, '', null);
        break;
      case 'service_exited':
        state.ready = false;
        state.active = false;
        state.phase = 'unavailable';
        pendingSettings = null;
        notice('Сервис завершился. Перезапустите приложение для проверки восстановления.', true, true);
        break;
      case 'error':
        state.checking = false;
        rulesBusy = false;
        setRulesBusy();
        editorBusy = false;
        controlsLocked = null;
        if (data.operation === 'save_settings') {
          pendingSettings = null;
          updateSaveState();
        }
        if (data.operation === 'delete_profile' && state.panel === 'profiles') renderProfiles();
        if (data.operation === 'start') {
          state.active = false;
          state.phase = 'idle';
        }
        if (data.operation === 'probe' && state.active && state.phase !== 'stopping') state.phase = 'unverified';
        if (['stop', '_restart'].includes(data.operation) && state.active) state.phase = 'unverified';
        const target = {
          save_profile: 'profile-error',
          save_settings: savePanel === 'routing' ? 'routing-error' : 'settings-error',
          explain: 'route-explanation'
        } [data.operation];
        if (target && $(target)) {
          text(target, data.message);
          $(target).hidden = false;
        } else notice(data.message || 'Не удалось выполнить операцию.', true, true);
        if ($('save-profile')) {
          $('save-profile').disabled = locked();
          text('save-profile', 'Сохранить профиль');
        }
        if (state.panel === 'activity') renderActivity();
        break;
    }
    render();
  }

  function closePanel() {
    if (!state.panel) return;
    rememberDraft();
    state.panel = null;
    $('drawer-body').replaceChildren();
    $('panel-view').hidden = true;
    $('home-view').hidden = false;
    if (chartDirty) renderChart();
    renderNavigation();
    $('workspace').scrollTop = 0;
    if (returnFocus?.isConnected && returnFocus.getClientRects().length) returnFocus.focus();
    else $('page-title').focus();
  }

  function openPanel(name) {
    if (!titles[name]) return;
    if (state.panel === name) return;
    rememberDraft();
    if (!state.panel) returnFocus = document.activeElement;
    state.panel = name;
    editingId = null;
    $('drawer-body').replaceChildren($(name + '-template').content.cloneNode(true));
    $('home-view').hidden = true;
    $('panel-view').hidden = false;
    renderNavigation();
    if (name === 'profiles') setupProfiles();
    if (name === 'routing') setupRouting();
    if (name === 'settings') setupSettings();
    if (name === 'activity') {
      renderActivity();
      selectActivityTab(activityTab);
      send('get_analytics');
    }
    restoreDraft(name);
    controlsLocked = null;
    render();
    $('workspace').scrollTop = drafts.get(name)?.scroll || 0;
    $('page-title').focus({preventScroll: true});
  }

  function renderNavigation() {
    const page = state.panel || 'home';
    document.body.dataset.page = page;
    document.querySelector('.header-status').hidden = page === 'home';
    text('page-title', titles[page] || 'Обзор');
    document.querySelectorAll('.sidebar [data-panel],.sidebar [data-page]').forEach(button => {
      const active = (button.dataset.panel || button.dataset.page) === page;
      button.classList.toggle('selected', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
  }

  function rememberDraft() {
    if (!state.panel) return;
    const draft = {scroll: $('workspace').scrollTop};
    if (state.panel === 'profiles') {
      Object.assign(draft, {search: $('profile-search').value, editor: !$('profile-editor').hidden,
        value: $('edit-profile').value, name: $('edit-name').value, id: editingId});
      // Mask the key whenever leaving the editor.
      $('show-secret').checked = false;
      $('edit-profile').classList.remove('revealed');
    }
    const form = $(state.panel + '-form');
    if (form && state.panel !== 'profiles') {
      draft.fields = {};
      for (const el of form.elements) {
        if (!el.name || (el.type === 'radio' && !el.checked)) continue;
        const value = el.type === 'checkbox' ? el.checked : el.value;
        if (value !== state.settings[el.name]) draft.fields[el.name] = value;
      }
    }
    drafts.set(state.panel, draft);
  }

  function restoreDraft(name) {
    const draft = drafts.get(name);
    if (!draft) return;
    if (draft.fields) {
      const form = $(name + '-form');
      fillSettings(form, draft.fields);
      if (name === 'settings') form.elements.namedItem('capture').dispatchEvent(new Event('change'));
      if (name === 'routing') form.dispatchEvent(new Event('change'));
      updateSaveState();
    }
    if (name === 'profiles') {
      $('profile-search').value = draft.search;
      renderProfiles();
      if (draft.editor && (!draft.id || state.profiles.some(p => p.id === draft.id))) {
        openEditor(draft.value, draft.name, draft.id, false);
      }
    }
  }

  function refreshControls() {
    const isLocked = locked() || !state.ready;
    if (controlsLocked !== isLocked) {
      controlsLocked = isLocked;
      if (state.panel === 'profiles') {
        renderProfiles();
        $('add-profile').disabled = isLocked || editorBusy;
        $('cancel-editor').disabled = editorBusy;
        $('profile-form').querySelectorAll('input,textarea,button').forEach(el => el.disabled = isLocked || editorBusy);
      }
    }
    for (const name of ['routing', 'settings']) {
      const form = $(name + '-form');
      if (!form) continue;
      form.querySelectorAll('input,textarea,select').forEach(el => el.disabled = isLocked || !!pendingSettings);
      if (name === 'routing' && form.elements.namedItem('preset').value === 'original') {
        ['direct', 'proxy', 'block', 'ru_ip'].forEach(key => form.elements.namedItem(key).disabled = true);
      }
      if (name === 'settings') {
        const mode = form.elements.namedItem('capture');
        mode.querySelector('[value=system]').disabled = !!conflict();
        mode.querySelector('[value=tun]').disabled = !!conflict();
      }
    }
    if ($('activity-check')) $('activity-check').disabled = !state.active || state.checking || state.phase === 'stopping';
    const recovery = document.querySelector('[data-action="recover_network"]');
    if (recovery) recovery.disabled = isLocked;
    setRulesBusy();
    updateSaveState();
  }

  function updateSaveState() {
    for (const name of ['routing', 'settings']) {
      const form = $(name + '-form');
      if (!form) continue;
      const next = formSettings(form);
      const dirty = Object.keys(defaults).some(key => next[key] !== state.settings[key]);
      const busy = !!pendingSettings;
      const button = form.querySelector('button[type=submit]');
      button.disabled = !dirty || locked() || busy || !state.ready;
      button.textContent = busy ? 'Сохраняем…' : name === 'routing' ? 'Сохранить маршруты' : 'Сохранить настройки';
      form.querySelector('.save-bar').classList.toggle('dirty', dirty);
      text(name + '-save-status', busy ? 'Сохраняем изменения' : dirty ? 'Есть несохранённые изменения' : 'Все изменения сохранены');
    }
  }

  function selectActivityTab(tab) {
    activityTab = tab;
    $('connection-activity').hidden = tab !== 'connection';
    $('analytics-box').hidden = tab !== 'history';
    document.querySelectorAll('[data-activity-tab]').forEach(button => {
      const active = button.dataset.activityTab === tab;
      button.classList.toggle('selected', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  function node(tag, className, content) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content !== undefined) el.textContent = content;
    return el;
  }

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + name);
    svg.setAttribute('aria-hidden', 'true');
    svg.append(use);
    return svg;
  }

  function renderProfiles() {
    const list = $('profile-list');
    if (!list) return;
    list.replaceChildren();
    const query = ($('profile-search')?.value || '').trim().toLocaleLowerCase('ru');
    const profiles = state.profiles.filter(p => `${p.name} ${p.protocol}`.toLocaleLowerCase('ru').includes(query));
    if (!profiles.length) {
      const empty = node('div', 'empty-state');
      empty.append(icon(query ? 'search' : 'rosette'), node('h3', '', query ? 'Ничего не нашлось' : 'Нет профилей'),
        node('p', '', query ? 'Попробуйте другое название или протокол.' : 'Добавьте ссылку от своего сервера или импортируйте файл конфигурации.'));
      if (!query) {
        const add = node('button', 'primary', 'Добавить профиль');
        add.onclick = () => openEditor('', '', null);
        add.disabled = locked() || editorBusy;
        empty.append(add);
      }
      list.append(empty);
      return;
    }
    for (const p of profiles) {
      const row = node('div', 'profile-row' + (p.id === state.selected ? ' selected' : ''));
      const choose = node('button', 'profile-choice');
      choose.type = 'button';
      choose.disabled = locked() || editorBusy || !state.ready;
      choose.setAttribute('aria-pressed', String(p.id === state.selected));
      const badge = node('span', 'choice-dot');
      badge.append(icon(p.id === state.selected ? 'check' : 'server'));
      choose.append(badge);
      const caption = node('span');
      caption.append(node('strong', '', p.name), node('small', '', String(p.protocol).toUpperCase() + (p.id === state.selected ? ' · Выбран' : '')));
      choose.append(caption);
      choose.onclick = () => {
        if (locked() || editorBusy || pendingSettings) return;
        selectProfile(p.id);
        closePanel();
      };
      const edit = node('button', 'icon-button edit-profile');
      edit.append(icon('edit'));
      edit.title = 'Редактировать профиль';
      edit.setAttribute('aria-label', 'Редактировать ' + p.name);
      edit.disabled = locked() || editorBusy || !state.ready;
      edit.onclick = () => send('get_profile', {
        profile_id: p.id
      });
      const del = node('button', 'icon-button delete-profile');
      del.append(icon('trash'));
      del.title = 'Удалить профиль';
      del.setAttribute('aria-label', 'Удалить ' + p.name);
      del.disabled = locked() || editorBusy || !state.ready;
      del.onclick = () => {
        if (locked() || editorBusy) return;
        pendingDeletion = p.id;
        text('confirm-message', `«${p.name}» будет удалён с этого устройства. Чтобы подключиться снова, понадобится исходная ссылка или файл.`);
        $('confirm-dialog').showModal();
        $('confirm-cancel').focus();
      };
      row.append(choose, edit, del);
      list.append(row);
    }
  }

  function setupProfiles() {
    renderProfiles();
    $('add-profile').disabled = locked();
    $('add-profile').onclick = () => openEditor('', '', null);
    $('cancel-editor').onclick = () => { clearEditor(); $('add-profile').focus(); };
    $('profile-search').oninput = renderProfiles;
    $('import-file').onclick = () => send('import_file');
    $('show-secret').onchange = e => $('edit-profile').classList.toggle('revealed', e.target.checked);
    const temporary = node('button', 'secondary full-width temporary-connect', 'Подключить без сохранения');
    temporary.id = 'temporary-connect';
    temporary.type = 'button';
    temporary.onclick = () => {
      if (locked() || editorBusy) return;
      const value = $('edit-profile').value.trim();
      if (!value) { $('edit-profile').focus(); return; }
      state.transient = {name: $('edit-name').value.trim() || 'Временный профиль',
        text: value, protocol: value.startsWith('{') ? 'JSON Xray' : (value.split('://')[0] || 'Профиль')};
      if (value.startsWith('{')) state.settings.preset = 'original';
      clearEditor();
      closePanel();
      $('connect-button').click();
    };
    $('profile-form').append(temporary);
    $('profile-form').onsubmit = e => {
      e.preventDefault();
      if (editorBusy || locked() || !state.ready) return;
      editorBusy = true;
      $('save-profile').disabled = true;
      $('temporary-connect').disabled = true;
      $('add-profile').disabled = true;
      text('save-profile', 'Сохраняем…');
      $('profile-error').hidden = true;
      controlsLocked = null;
      refreshControls();
      send('save_profile', {
        profile: $('edit-profile').value,
        name: $('edit-name').value,
        profile_id: editingId
      });
    };
  }

  function clearEditor() {
    editingId = null;
    $('profile-form').reset();
    $('edit-profile').classList.remove('revealed');
    $('profile-editor').hidden = true;
    $('profile-error').hidden = true;
    drafts.delete('profiles');
    editorBusy = false;
    controlsLocked = null;
    refreshControls();
  }

  function openEditor(value, name, id, focus = true) {
    if (editorBusy && focus) return;
    editingId = id;
    $('profile-editor').hidden = false;
    $('edit-profile').value = value;
    $('edit-name').value = name;
    $('show-secret').checked = false;
    $('edit-profile').classList.remove('revealed');
    $('profile-error').hidden = true;
    text('editor-title', id ? 'Редактировать профиль' : 'Новый профиль');
    $('save-profile').disabled = locked() || editorBusy;
    text('save-profile', editorBusy ? 'Сохраняем…' : 'Сохранить профиль');
    if (focus) $('edit-profile').focus();
  }

  function formSettings(form) {
    const next = {
      ...state.settings
    };
    for (const key of Object.keys(defaults)) {
      const element = form.elements.namedItem(key);
      if (element) {
        next[key] = ['ru_ip', 'auto_reconnect'].includes(key) ? element.checked : element.value;
      }
    }
    return next;
  }

  function fillSettings(form, settings = state.settings) {
    for (const [key, value] of Object.entries(settings)) {
      const el = form.elements.namedItem(key);
      if (!el) continue;
      if (el instanceof RadioNodeList) {
        el.value = value;
      } else if (el.type === 'checkbox') el.checked = value;
      else el.value = value;
    }
  }

  function saveSettings(form, panel) {
    if (pendingSettings || !state.ready) return;
    if (locked()) {
      notice('Отключитесь перед изменением настроек.', true);
      return;
    }
    savePanel = panel;
    pendingSettings = formSettings(form);
    $(panel + '-error').hidden = true;
    refreshControls();
    send('save_settings', {
      settings: pendingSettings
    });
  }

  function setupRouting() {
    const form = $('routing-form');
    fillSettings(form);
    if (conflict()) form.before(node('p', 'info-box',
      'При включённом другом VPN маршрут «напрямую» использует текущее подключение Windows.'));
    const json = String(selected()?.protocol).toLowerCase().includes('json');
    $('original-option').hidden = !json;
    form.onsubmit = e => {
      e.preventDefault();
      saveSettings(form, 'routing');
    };
    form.querySelectorAll('input,textarea,button').forEach(el => el.disabled = locked());
    const original = () => {
      const isOriginal = form.elements.namedItem('preset').value === 'original';
      ['direct', 'proxy', 'block', 'ru_ip'].forEach(k => form.elements.namedItem(k).disabled =
        locked() || isOriginal);
    };
    form.onchange = () => { original(); updateSaveState(); };
    form.oninput = updateSaveState;
    original();
    $('explain-form').onsubmit = e => {
      e.preventDefault();
      send('explain', {
        target: $('explain-target').value,
        settings: formSettings(form)
      });
    };
    rulesVersion();
    setRulesBusy();
  }

  function rulesVersion() {
    text('rules-version', (state.rules.version || state.rules.commit?.slice(0, 12) ||
      'Встроенные списки Xray') + (state.rules.updated ? ' · ' + new Date(state.rules.updated *
      1000).toLocaleDateString('ru-RU') : ''));
  }

  function setRulesBusy() {
    document.querySelectorAll('[data-action="update_rules"],[data-action="rollback_rules"]').forEach(
      el => el.disabled = rulesBusy || locked());
  }

  function setupSettings() {
    const form = $('settings-form');
    fillSettings(form);
    const mode = form.elements.namedItem('capture');
    if (conflict()) {
      mode.querySelector('[value=system]').disabled = true;
      mode.querySelector('[value=tun]').disabled = true;
    }
    const hint = () => {
      text('capture-hint', {
        local: 'Для отдельного браузера или приложений с ручной настройкой прокси.',
        system: 'Браузеры и программы, которые используют системный прокси Windows. Для UDP и остальных программ используйте TUN.',
        tun: 'Все приложения, включая UDP. При подключении подтвердите права для сетевого помощника в окне Windows. Интерфейс работает с обычными правами. Другой VPN и системный прокси должны быть отключены.'
      } [mode.value]);
    };
    mode.onchange = () => { hint(); updateSaveState(); };
    form.oninput = updateSaveState;
    form.addEventListener('change', updateSaveState);
    hint();
    const refresh = node('button', 'text-button', 'Проверить другие VPN');
    refresh.type = 'button';
    refresh.onclick = () => send('refresh_environment');
    $('capture-hint').after(refresh);
    form.onsubmit = e => {
      e.preventDefault();
      saveSettings(form, 'settings');
    };
    form.querySelectorAll('input,select').forEach(el => { el.disabled = locked(); });
    $('theme-select').value = theme;
    $('theme-select').onchange = e => applyTheme(e.target.value);
    $('reduce-motion').checked = document.body.classList.contains('reduce-motion');
    $('reduce-motion').onchange = e => {
      document.body.classList.toggle('reduce-motion', e.target.checked);
      privateUiSet('reduce-motion', e.target.checked);
    };
    document.querySelector('[data-action="recover_network"]').disabled = locked();
  }

  function renderActivity() {
    if (!$('sites-list')) return;
    const btn = $('activity-check');
    btn.disabled = !state.active || state.checking;
    btn.textContent = state.checking ? 'Проверяем…' : 'Проверить сайты';
    const exits = state.sites?.exit;
    text('exit-info', exits ?
      `Сервер: ${exits.profile?.country||'не определён'} · Маршрут ChatGPT: ${exits.chatgpt_route?.country||'не определён'}` :
      'Страна выхода ещё не проверена.');
    const sites = $('sites-list');
    sites.replaceChildren();
    if (!state.sites?.results?.length) sites.append(node('p', 'sites-empty', state.checking ?
      'Проверяем соединение с сайтами…' : state.active ? 'Нажмите «Проверить сайты», чтобы увидеть результат.' :
      'Подключитесь к серверу, чтобы проверить доступность сайтов.'));
    for (const item of state.sites?.results || []) {
      const row = node('div', 'site-row');
      const caption = node('div');
      caption.append(node('strong', '', item.target), node('small', '', item.transport_ok ?
        `HTTPS работает · ${item.elapsed_ms} мс` : 'HTTPS-соединение не установлено'));
      row.append(caption, node('span', 'site-state' + (item.accessible ? '' : item.transport_ok ?
          ' denied' : ' failed'), item.accessible ? `HTTP ${item.http_status}` : item
        .transport_ok ? `Сайт: ${item.http_status}` : 'Нет связи'));
      sites.append(row);
    }
    const events = $('activity-list');
    events.replaceChildren();
    for (const event of state.events) {
      const li = node('li', event.severity || event.level || '');
      li.append(node('time', '', new Date(event.received).toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit'
      })), node('span', '', event.message));
      events.append(li);
    }
    if (!state.events.length) events.append(node('li', '', 'Нет событий.'));
    renderAnalytics();
  }

  function renderAnalytics() {
    if (!$('activity-list')) return;
    let box = $('analytics-box');
    if (!box) {
      box = node('div');
      box.id = 'analytics-box';
      $('activity-list').parentElement.append(box);
    }
    box.replaceChildren();
    box.append(node('h3', '', 'История подключений'));
    const total = state.analytics?.total;
    if (!total) {
      box.append(node('p', 'muted small', 'Нет завершённых сессий.'));
      return;
    }
    const grid = node('div', 'analytics-grid');
    for (const [label, value] of [
      ['Сессий', total.sessions || 0],
      ['Общее время', duration(total.duration || 0)],
      ['Получено', bytes(total.download_bytes)],
      ['Отправлено', bytes(total.upload_bytes)],
      ['Средний HTTPS', total.average_https_ms == null ? '—' : total.average_https_ms + ' мс'],
      ['Переподключений', total.reconnects || 0]
    ]) {
      const metric = node('div');
      metric.append(node('span', '', label), node('strong', '', value));
      grid.append(metric);
    }
    box.append(grid);
    const recent = node('div', 'recent-sessions');
    for (const row of state.analytics.recent || []) {
      const item = node('div', 'site-row');
      const caption = node('div');
      caption.append(node('strong', '', new Date(row.started * 1000).toLocaleString('ru-RU', {
        day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'
      })), node('small', '', `${duration(row.duration || 0)} · ↓ ${bytes(row.download_bytes)} · ↑ ${bytes(row.upload_bytes)}`));
      item.append(caption, node('span', 'site-state' + (row.interrupted ? ' denied' : ''),
        row.interrupted ? 'Прервана' : row.country || 'Завершена'));
      recent.append(item);
    }
    box.append(recent, node('p', 'muted small', 'Хранится только время и статистика сессий, с защитой Windows. После сбоя — последний сохранённый снимок. История не содержит посещённые сайты.'));
  }

  document.addEventListener('click', e => {
    const home = e.target.closest('button[data-page="home"]');
    if (home) { closePanel(); return; }
    const tab = e.target.closest('[data-activity-tab]');
    if (tab) { selectActivityTab(tab.dataset.activityTab); return; }
    const copy = e.target.closest('[data-copy]');
    if (copy) { copyAddress(copy.dataset.copy); return; }
    const panel = e.target.closest('[data-panel]');
    if (panel) {
      openPanel(panel.dataset.panel);
      return;
    }
    const action = e.target.closest('[data-action]');
    if (action && !action.disabled) {
      if (action.dataset.action === 'check_sites') {
        if (!state.active || state.checking) return;
        if (state.panel === 'activity') selectActivityTab('connection');
        state.checking = true;
        if (state.panel === 'activity') renderActivity();
        render();
      }
      send(action.dataset.action);
    }
  });
  $('connect-button').onclick = () => {
    if (!state.ready || pendingSettings || editorBusy || state.phase === 'stopping') return;
    if (locked()) {
      state.phase = 'stopping';
      send('stop');
    } else if (!selected()) {
      openPanel('profiles');
      openEditor('', '', null);
    } else {
      state.phase = 'connecting';
      send('start', state.transient ? {profile: state.transient.text, settings: state.settings} : {
        profile_id: state.selected, settings: state.settings
      });
    }
    render();
  };
  $('unlock-settings').onclick = () => $('connect-button').click();
  $('home-profile').onchange = e => selectProfile(e.target.value);
  $('home-capture').onchange = e => saveHomeSetting('capture', e.target.value);
  $('home-preset').onchange = e => saveHomeSetting('preset', e.target.value);
  $('home-add-profile').onclick = () => { openPanel('profiles'); openEditor('', '', null); };
  document.addEventListener('visibilitychange', () => { if (!document.hidden && chartDirty) renderChart(); });
  $('theme-toggle').onclick = () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  $('confirm-cancel').onclick = () => $('confirm-dialog').close();
  $('confirm-dialog').addEventListener('close', () => { pendingDeletion = null; });
  $('confirm-delete').onclick = () => {
    if (pendingDeletion && !locked()) {
      const id = pendingDeletion;
      if (editingId === id && $('profile-editor')) clearEditor();
      send('delete_profile', {profile_id: id});
    }
    $('confirm-dialog').close();
  };
  $('toast-close').onclick = () => {
    $('toast').hidden = true;
    clearTimeout(toastTimer);
  };
  document.querySelector('.brand').onclick = e => {
    e.preventDefault();
    closePanel();
  };
  document.addEventListener('keydown', e => {
    if ($('confirm-dialog').open) {
      if (e.key === 'Tab') {
        const first = $('confirm-cancel'), last = $('confirm-delete');
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
      return;
    }
    if (e.ctrlKey && !e.altKey && !e.shiftKey && e.key === 'Enter' && !e.repeat &&
        !e.target.closest('input,textarea,select,[contenteditable=true]')) {
      e.preventDefault();
      $('connect-button').click();
      return;
    }
    if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && /^[1-5]$/.test(e.key)) {
      e.preventDefault();
      const page = ['home', 'profiles', 'routing', 'activity', 'settings'][Number(e.key) - 1];
      if (page === 'home') closePanel(); else openPanel(page);
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's' && ['profiles', 'routing', 'settings'].includes(state.panel)) {
      e.preventDefault();
      const form = $(state.panel === 'profiles' ? 'profile-form' : state.panel + '-form');
      const submit = form.querySelector('button[type=submit]');
      if (!submit.disabled && submit.getClientRects().length) form.requestSubmit();
    }
    if (e.key === 'Escape') {
      if (!$('toast').hidden) $('toast').hidden = true;
      else if (state.panel && !e.target.matches('input,textarea,select')) closePanel();
    }
  });

  async function copyAddress(value) {
    try {
      await navigator.clipboard.writeText(value);
      notice('Адрес скопирован: ' + value);
    } catch {
      // WebView2 may deny the clipboard API; user-triggered selection still works.
      const previous = document.activeElement;
      const field = node('textarea');
      field.value = value;
      field.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.append(field);
      field.select();
      const copied = document.execCommand('copy');
      field.remove();
      previous?.focus();
      notice(copied ? 'Адрес скопирован: ' + value : 'Скопируйте адрес вручную: ' + value, !copied);
    }
  }
  $('titlebar').addEventListener('pointerdown', e => {
    if (e.button === 0 && !e.target.closest('button,a')) send('window_drag');
  });
  $('titlebar').addEventListener('dblclick', e => {
    if (!e.target.closest('button,a')) send('window_maximize');
  });
  if (bridge) bridge.addEventListener('message', e => receive(e.data));
  // Read-only state and event injection are used by the native smoke/integration harness.
  // No privileged action is exposed beyond the origin-checked native bridge.
  window.yukiwire = Object.freeze({
    receive,
    openPanel,
    closePanel,
    summary: () => ({
      ready: state.ready,
      phase: state.phase,
      active: state.active,
      panel: state.panel,
      sampleCount: state.samples.length,
      profileCount: state.profiles.length
    })
  });
  render();
  renderNavigation();
  renderChart();
  send('ui_ready');
})();
