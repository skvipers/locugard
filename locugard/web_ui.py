"""Встроенный опциональный веб-интерфейс LocuGard (без внешних CDN и без токенов в localStorage)."""
from __future__ import annotations

WEB_UI_HTML = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LocuGard — Управление доступом</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml" />
  <link rel="icon" href="/favicon.ico" sizes="any" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
  <style>
    :root {
      color-scheme: dark light;
      --bg: #0c0f14;
      --surface: #141923;
      --surface-2: #1b2230;
      --border: rgba(255, 255, 255, 0.09);
      --text: #edf1f7;
      --muted: #94a3b8;
      --accent: #0f766e;
      --accent-hover: #0d9488;
      --accent-soft: #2dd4bf;
      --success: #22c55e;
      --warning: #f59e0b;
      --danger: #ef4444;
      --radius: 12px;
      --shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f4f6fa;
        --surface: #ffffff;
        --surface-2: #f8fafc;
        --border: rgba(15, 23, 42, 0.1);
        --text: #0f172a;
        --muted: #475569;
        --accent-soft: #0f766e;
        --shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
    }
    .wrap { max-width: 960px; margin: 0 auto; padding: 28px 20px 64px; }
    header.topbar {
      display: flex; align-items: center; justify-content: space-between;
      gap: 16px; flex-wrap: wrap;
      padding: 14px 18px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      margin-bottom: 22px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo { width: 38px; height: 38px; border-radius: 10px; display: block; flex-shrink: 0; }
    .brand h1 { margin: 0; font-size: 17px; letter-spacing: -0.01em; }
    .brand small { display: block; color: var(--muted); font-size: 12px; }
    .row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .pill {
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 12px; font-weight: 600;
      padding: 4px 10px; border-radius: 999px;
      background: var(--surface-2); border: 1px solid var(--border); color: var(--text);
    }
    .pill.ok { border-color: rgba(34, 197, 94, 0.35); color: var(--success); }
    .pill.warn { border-color: rgba(245, 158, 11, 0.4); color: var(--warning); }
    .pill.danger { border-color: rgba(239, 68, 68, 0.4); color: var(--danger); }
    .pill.accent { border-color: rgba(15, 118, 110, 0.5); color: var(--accent-soft); }
    button {
      font: inherit; font-size: 13.5px; font-weight: 600;
      padding: 8px 14px; border-radius: 9px;
      border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
      cursor: pointer; transition: background 0.15s, border-color 0.15s, transform 0.05s;
    }
    button:hover { border-color: rgba(148, 163, 184, 0.45); }
    button:active { transform: translateY(1px); }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.primary:hover { background: var(--accent-hover); }
    button.danger { background: rgba(239, 68, 68, 0.14); border-color: rgba(239, 68, 68, 0.4); color: #fca5a5; }
    @media (prefers-color-scheme: light) {
      button.danger { color: #b91c1c; }
    }
    button.danger:hover { background: rgba(239, 68, 68, 0.24); }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    input, select {
      font: inherit; font-size: 14px;
      padding: 9px 12px; border-radius: 9px;
      border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
      width: 100%;
    }
    input:focus { outline: 2px solid rgba(59, 130, 246, 0.45); outline-offset: 1px; }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 20px; box-shadow: var(--shadow);
      margin-bottom: 16px;
    }
    .card h2 { margin: 0 0 6px; font-size: 16px; }
    .card p.sub { margin: 0 0 16px; color: var(--muted); font-size: 13.5px; }
    .login-shell { max-width: 420px; margin: 56px auto; text-align: center; padding: 28px 24px; }
    .login-brand { display: inline-flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 14px; }
    .login-brand img { width: 46px; height: 46px; border-radius: 12px; display: block; }
    .login-wordmark { font-size: 28px; font-weight: 700; letter-spacing: -0.04em; }
    .login-wordmark span:first-child { color: var(--accent-soft); }
    .login-shell button.primary { width: 100%; padding: 11px 16px; font-size: 15px; margin-top: 8px; }
    .tabs { display: flex; gap: 6px; margin-bottom: 18px; flex-wrap: wrap; }
    .tab {
      padding: 8px 14px; border-radius: 9px; border: 1px solid transparent;
      background: transparent; color: var(--muted); font-weight: 600; font-size: 13.5px;
    }
    .tab.active { background: var(--surface); border-color: var(--border); color: var(--text); }
    .hidden { display: none !important; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    .kv { background: var(--surface-2); border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px; }
    .kv label { display: block; font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .kv .val { font-family: var(--mono); font-size: 13px; margin-top: 3px; word-break: break-all; }
    .list { display: flex; flex-direction: column; gap: 10px; }
    .item {
      display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap;
      padding: 12px 14px; border-radius: 10px;
      background: var(--surface-2); border: 1px solid var(--border);
    }
    .item-meta { font-size: 12.5px; color: var(--muted); margin-top: 2px; font-family: var(--mono); }
    .codebox {
      font-family: var(--mono); font-size: 12.5px;
      background: var(--surface-2); border: 1px solid var(--border);
      border-radius: 9px; padding: 12px; word-break: break-all; white-space: pre-wrap;
    }
    .codes-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; margin: 14px 0; }
    .code-cell {
      font-family: var(--mono); font-size: 13.5px; font-weight: 600; text-align: center;
      padding: 10px; border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border);
    }
    .toast {
      position: fixed; right: 20px; bottom: 20px; max-width: 380px;
      padding: 12px 16px; border-radius: 10px; font-size: 13.5px;
      background: var(--surface); border: 1px solid var(--border); box-shadow: var(--shadow);
      z-index: 50;
    }
    .toast.ok { border-color: rgba(34, 197, 94, 0.55); }
    .toast.err { border-color: rgba(239, 68, 68, 0.65); }
    .notice {
      padding: 10px 14px; border-radius: 9px; font-size: 13px;
      background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.35);
      margin-bottom: 14px;
    }
    .empty { color: var(--muted); font-size: 13.5px; padding: 10px 0; }
  </style>
</head>
<body>
  <div class="wrap">
    <div id="viewLogin" class="card login-shell">
      <div class="login-brand">
        <img src="/assets/favicon.svg" alt="LocuGard" />
        <div class="login-wordmark"><span>locu</span><span>gard</span></div>
      </div>
      <p class="sub">Используйте Passkey, биометрию или ключ безопасности.</p>
      <button class="primary" id="btnLogin" onclick="doLogin()">Войти</button>
      <p class="sub hidden" style="margin-top:12px;font-size:12px;color:var(--warning)" id="secHint"></p>
    </div>

    <div id="viewApp" class="hidden">
      <header class="topbar">
        <div class="brand">
          <img class="brand-logo" src="/assets/favicon.svg" alt="LocuGard" />
          <div>
            <h1 id="hdrName">LocuGard</h1>
            <small id="hdrSub">Защищённая сессия</small>
          </div>
        </div>
        <div class="row">
          <span class="pill accent" id="pillRole">role</span>
          <span class="pill ok" id="pillMode">Режим 2</span>
          <span class="pill" id="pillZone">LAN</span>
          <button onclick="doReauth()">Обновить личность</button>
          <button class="danger" onclick="doLogout()">Выйти</button>
        </div>
      </header>

      <div id="csrfNotice" class="notice hidden">
        Страница была перезагружена — для изменяющих операций нажмите <button onclick="doLogin()" style="margin-left:6px">Подтвердить Passkey</button>
      </div>

      <nav class="tabs">
        <button class="tab active" data-tab="session" onclick="switchTab('session')">Сессия</button>
        <button class="tab" data-tab="devices" onclick="switchTab('devices')">Устройства</button>
        <button class="tab" data-tab="actions" onclick="switchTab('actions')">Опасные действия</button>
        <button class="tab" data-tab="recovery" onclick="switchTab('recovery')">Recovery-коды</button>
      </nav>

      <section id="tab-session" class="card">
        <h2>Текущая сессия</h2>
        <p class="sub">Контекст проверен сервером по криптографической связке аккаунт ↔ устройство ↔ ключ.</p>
        <div class="grid-2" id="sessionGrid"></div>
      </section>

      <section id="tab-devices" class="hidden">
        <div class="card">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2>Зарегистрированные устройства</h2>
              <p class="sub" style="margin-bottom:0">Отзыв немедленно завершает все сессии и refresh-цепочки устройства.</p>
            </div>
            <button onclick="loadDevices()">Обновить</button>
          </div>
          <div class="list" id="devicesList"></div>
        </div>

        <div class="card" id="ownerEnrollCard">
          <h2>Добавить новое устройство</h2>
          <p class="sub">Создаёт одноразовый код регистрации (TTL 5 минут). Подходит для нового браузера и нативного приложения (Flutter).</p>
          <div class="row">
            <input id="enrollTarget" placeholder="account_id (пусто = текущий аккаунт)" style="max-width:300px" />
            <button class="primary" onclick="doCreateEnrollment()">Создать код регистрации</button>
          </div>
          <div id="enrollResult" class="hidden" style="margin-top:14px">
            <div class="codebox" id="enrollBox"></div>
            <div class="row" style="margin-top:8px">
              <button onclick="copyText(document.getElementById('enrollBox').textContent)">Скопировать JSON</button>
            </div>
          </div>
        </div>

        <div class="card" id="ownerPendingCard">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2>Ожидающие заявки на регистрацию</h2>
              <p class="sub" style="margin-bottom:0">Сверьте отпечаток ключа (<code>key_fingerprint</code>) перед одобрением.</p>
            </div>
            <button onclick="loadPending()">Обновить</button>
          </div>
          <div class="list" id="pendingList"></div>
        </div>
      </section>

      <section id="tab-actions" class="card hidden">
        <h2>Опасные действия (Permissions)</h2>
        <p class="sub">Двухшаговое подтверждение: свежая проверка личности + неизменяемый <code>action_digest</code> и повторная проверка прав при исполнении.</p>
        <div class="grid-2" style="margin-bottom:12px">
          <div>
            <label style="font-size:12px;color:var(--muted)">Цель действия</label>
            <input id="actTarget" value="demo-target" />
          </div>
          <div>
            <label style="font-size:12px;color:var(--muted)">Комментарий</label>
            <input id="actNote" placeholder="причина операции" />
          </div>
        </div>
        <button class="primary" onclick="doDangerReq()">Запросить опасное действие</button>

        <div id="approvalCard" class="hidden" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
          <div class="kv" style="margin-bottom:10px">
            <label>Описание</label>
            <div class="val" id="apprDesc" style="font-family:var(--sans)"></div>
          </div>
          <div class="kv" style="margin-bottom:12px">
            <label>Action Digest (SHA-256)</label>
            <div class="val" id="apprDigest"></div>
          </div>
          <div class="row">
            <button class="primary" onclick="doDangerConf()">Подтвердить и выполнить</button>
            <button onclick="clearApproval()">Сбросить</button>
          </div>
        </div>
      </section>

      <section id="tab-recovery" class="card hidden">
        <h2>Офлайн Recovery-коды</h2>
        <p class="sub">Одноразовый запасной путь для владельца (<code>owner</code>). Выпуск нового набора отзывает прежний; коды показываются один раз.</p>
        <button class="primary" onclick="doGenRecovery()">Сгенерировать 10 recovery-кодов</button>
        <div id="recoveryWrap" class="hidden">
          <div class="codes-grid" id="recoveryGrid"></div>
          <div class="row">
            <button onclick="copyRecovery()">Скопировать все</button>
            <button onclick="downloadRecovery()">Скачать .txt</button>
          </div>
        </div>
      </section>
    </div>
  </div>
  <div id="toast" class="toast hidden"></div>

  <script>
    let csrf = "";
    let profile = null;
    let lastApproval = null;
    let lastRecoveryCodes = [];

    const $ = (id) => document.getElementById(id);
    const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

    let toastTimer = null;
    function toast(msg, kind = "ok") {
      const el = $("toast");
      el.textContent = msg;
      el.className = "toast " + kind;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => el.classList.add("hidden"), 4200);
    }

    function copyText(text) {
      navigator.clipboard.writeText(text).then(() => toast("Скопировано в буфер обмена")).catch(() => toast("Не удалось скопировать", "err"));
    }

    function switchTab(name) {
      document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
      ["session", "devices", "actions", "recovery"].forEach(t => $("tab-" + t).classList.toggle("hidden", t !== name));
      if (name === "devices") { loadDevices(); if (profile && profile.role === "owner") loadPending(); }
    }

    function renderProfile() {
      if (!profile) {
        $("viewLogin").classList.remove("hidden");
        $("viewApp").classList.add("hidden");
        return;
      }
      $("viewLogin").classList.add("hidden");
      $("viewApp").classList.remove("hidden");
      $("csrfNotice").classList.toggle("hidden", Boolean(csrf));
      $("hdrName").textContent = profile.display_name || profile.account_id;
      $("hdrSub").textContent = "Устройство: " + profile.device_id;
      $("pillRole").textContent = profile.role;
      $("pillMode").textContent = "Режим " + profile.effective_mode;
      $("pillZone").textContent = profile.network_zone === "lan" ? "LAN" : "Вне LAN";
      $("ownerEnrollCard").classList.toggle("hidden", profile.role !== "owner");
      $("ownerPendingCard").classList.toggle("hidden", profile.role !== "owner");

      const fields = [
        ["Account ID", profile.account_id],
        ["Имя", profile.display_name || "—"],
        ["Роль", profile.role],
        ["Device ID", profile.device_id],
        ["Зона сети", profile.network_zone],
        ["Эффективный режим", "Режим " + profile.effective_mode]
      ];
      $("sessionGrid").innerHTML = fields.map(([k, v]) => `<div class="kv"><label>${k}</label><div class="val">${escapeHtml(String(v))}</div></div>`).join("");
    }

    function escapeHtml(s) {
      return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }

    async function api(url, opts = {}) {
      const headers = Object.assign({}, opts.headers || {});
      if (opts.method && opts.method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
      if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const r = await fetch(url, Object.assign({}, opts, { headers }));
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
      return data;
    }

    async function checkSession() {
      if (!window.isSecureContext) {
        $("secHint").textContent = "Для входа по Passkey требуется HTTPS.";
        $("secHint").classList.remove("hidden");
      }
      try {
        profile = await api("/api/protected/profile");
        renderProfile();
      } catch {
        profile = null;
        renderProfile();
      }
    }

    async function doLogin() {
      try {
        const { challenge_id, options } = await api("/auth/login/options", { method: "POST" });
        options.challenge = b64uToBuf(options.challenge);
        const cred = await navigator.credentials.get({ publicKey: options });
        const body = await api("/auth/login/verify", {
          method: "POST",
          body: JSON.stringify({
            challenge_id,
            credential: {
              id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
              response: {
                authenticatorData: bufToB64u(cred.response.authenticatorData),
                clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                signature: bufToB64u(cred.response.signature),
                userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
              }
            }
          })
        });
        csrf = body.csrf_token || "";
        profile = await api("/api/protected/profile");
        renderProfile();
        toast("Вход выполнен");
      } catch (e) {
        toast("Ошибка входа: " + e.message, "err");
      }
    }

    async function doReauth() {
      try {
        const { challenge_id, options } = await api("/auth/reauth/options", { method: "POST" });
        options.challenge = b64uToBuf(options.challenge);
        if (options.allowCredentials) options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: b64uToBuf(c.id) }));
        const cred = await navigator.credentials.get({ publicKey: options });
        await api("/auth/reauth/verify", {
          method: "POST",
          body: JSON.stringify({
            challenge_id,
            credential: {
              id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
              response: {
                authenticatorData: bufToB64u(cred.response.authenticatorData),
                clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                signature: bufToB64u(cred.response.signature),
                userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
              }
            }
          })
        });
        toast("Личность повторно подтверждена");
      } catch (e) {
        toast("Ошибка подтверждения: " + e.message, "err");
      }
    }

    async function doLogout() {
      try {
        await api("/auth/logout", { method: "POST" });
        csrf = ""; profile = null; lastApproval = null; lastRecoveryCodes = [];
        renderProfile();
        toast("Сессия завершена");
      } catch (e) {
        toast("Ошибка выхода: " + e.message, "err");
      }
    }

    async function loadDevices() {
      try {
        const { devices } = await api("/api/devices");
        if (!devices.length) { $("devicesList").innerHTML = '<div class="empty">Устройств нет</div>'; return; }
        $("devicesList").innerHTML = devices.map(d => {
          const stClass = d.state === "active" ? "ok" : (d.state === "pending" ? "warn" : "danger");
          const hw = d.hardware_binding ? "Аппаратный ключ" : "Программный / Passkey";
          const isCur = profile && d.device_id === profile.device_id;
          return `<div class="item">
            <div>
              <div class="row">
                <strong>${escapeHtml(d.display_name)}</strong>
                <span class="pill ${stClass}">${escapeHtml(d.state)}</span>
                ${isCur ? '<span class="pill accent">текущее</span>' : ''}
              </div>
              <div class="item-meta">${escapeHtml(d.device_id)} · ${escapeHtml(d.kind)} · ${hw} · активных сессий: ${d.active_sessions_count || 0}</div>
            </div>
            ${d.state !== "revoked" ? `<button class="danger" onclick="doRevokeDevice('${escapeHtml(d.device_id)}')">Отозвать</button>` : ''}
          </div>`;
        }).join("");
      } catch (e) {
        toast("Не удалось загрузить устройства: " + e.message, "err");
      }
    }

    async function doRevokeDevice(deviceId) {
      if (!confirm("Отозвать устройство " + deviceId + " и немедленно завершить все его сессии?")) return;
      try {
        await api("/api/devices/" + encodeURIComponent(deviceId) + "/revoke", { method: "POST" });
        toast("Устройство отозвано");
        if (profile && deviceId === profile.device_id) { csrf = ""; profile = null; renderProfile(); return; }
        loadDevices();
      } catch (e) {
        toast("Ошибка отзыва: " + e.message, "err");
      }
    }

    async function doCreateEnrollment() {
      try {
        const target = $("enrollTarget").value.trim();
        const data = await api("/api/devices/enrollment-codes", {
          method: "POST",
          body: JSON.stringify(target ? { target_account_id: target } : {})
        });
        $("enrollBox").textContent = JSON.stringify({
          origin: window.location.origin,
          enrollment_id: data.enrollment_id,
          secret: data.secret,
          allowed_role: data.allowed_role,
          expires_at: data.expires_at
        }, null, 2);
        $("enrollResult").classList.remove("hidden");
        toast("Одноразовый код регистрации создан (TTL 5 мин)");
      } catch (e) {
        toast("Ошибка создания кода: " + e.message, "err");
      }
    }

    async function loadPending() {
      try {
        const { requests } = await api("/api/devices/registrations");
        if (!requests.length) { $("pendingList").innerHTML = '<div class="empty">Ожидающих заявок нет</div>'; return; }
        $("pendingList").innerHTML = requests.map(r => `<div class="item">
          <div>
            <div class="row">
              <strong>${escapeHtml(r.device_name || r.device_id)}</strong>
              <span class="pill warn">${escapeHtml(r.requested_role)}</span>
              <span class="pill">${escapeHtml(r.device_kind || "device")}</span>
            </div>
            <div class="item-meta">ID: ${escapeHtml(r.request_id)} · Отпечаток: ${escapeHtml(r.key_fingerprint)}</div>
          </div>
          <button class="primary" onclick="doApprove('${escapeHtml(r.request_id)}')">Одобрить</button>
        </div>`).join("");
      } catch (e) {
        toast("Не удалось загрузить заявки: " + e.message, "err");
      }
    }

    async function doApprove(requestId) {
      try {
        await api("/api/devices/registrations/" + encodeURIComponent(requestId) + "/approve", { method: "POST", body: "{}" });
        toast("Устройство одобрено и активировано");
        loadPending(); loadDevices();
      } catch (e) {
        toast("Ошибка одобрения: " + e.message, "err");
      }
    }

    async function doDangerReq() {
      try {
        const target = $("actTarget").value.trim() || "demo-target";
        const note = $("actNote").value.trim();
        lastApproval = await api("/api/protected/dangerous-action/request", {
          method: "POST",
          body: JSON.stringify({ target, note })
        });
        $("apprDesc").textContent = lastApproval.description;
        $("apprDigest").textContent = lastApproval.action_digest;
        $("approvalCard").classList.remove("hidden");
        toast("Заявка создана — подтвердите действие в течение 120 с");
      } catch (e) {
        toast("Отклонено: " + e.message, "err");
      }
    }

    async function doDangerConf() {
      if (!lastApproval) return;
      try {
        const res = await api("/api/protected/dangerous-action/confirm", {
          method: "POST",
          body: JSON.stringify({ approval_id: lastApproval.approval_id, action_digest: lastApproval.action_digest })
        });
        toast("Выполнено: " + (res.status || "ok"));
        clearApproval();
      } catch (e) {
        toast("Ошибка выполнения: " + e.message, "err");
      }
    }

    function clearApproval() {
      lastApproval = null;
      $("approvalCard").classList.add("hidden");
    }

    async function doGenRecovery() {
      try {
        const data = await api("/api/recovery-codes", { method: "POST" });
        lastRecoveryCodes = data.codes || [];
        $("recoveryGrid").innerHTML = lastRecoveryCodes.map(c => `<div class="code-cell">${escapeHtml(c)}</div>`).join("");
        $("recoveryWrap").classList.remove("hidden");
        toast("Выпущен новый набор из " + lastRecoveryCodes.length + " recovery-кодов");
      } catch (e) {
        toast("Ошибка выпуска recovery-кодов: " + e.message, "err");
      }
    }

    function copyRecovery() { copyText(lastRecoveryCodes.join("\\n")); }
    function downloadRecovery() {
      const blob = new Blob(["LocuGard Recovery Codes (хранить офлайн)\\n\\n" + lastRecoveryCodes.join("\\n") + "\\n"], { type: "text/plain;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "locugard-recovery-codes.txt";
      a.click();
      URL.revokeObjectURL(a.href);
    }

    checkSession();
  </script>
</body>
</html>
"""


def render_web_ui() -> str:
    return WEB_UI_HTML
