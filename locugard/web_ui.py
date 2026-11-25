"""Встроенный опциональный веб-интерфейс LocuGard с локализацией EN/RU (без внешних CDN и без localStorage)."""
from __future__ import annotations

WEB_UI_HTML = """<!doctype html>
<html lang="__LOCUGARD_LANG__">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LocuGard</title>
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
    .lang-toggle {
      display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
      background: var(--surface-2);
    }
    .lang-toggle button {
      border: 0; border-radius: 0; padding: 5px 9px; font-size: 12px; background: transparent; color: var(--muted);
    }
    .lang-toggle button.active { background: var(--accent); color: #fff; }
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
    input:focus { outline: 2px solid rgba(15, 118, 110, 0.5); outline-offset: 1px; }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 20px; box-shadow: var(--shadow);
      margin-bottom: 16px;
    }
    .card h2 { margin: 0 0 6px; font-size: 16px; }
    .card p.sub { margin: 0 0 16px; color: var(--muted); font-size: 13.5px; }
    .login-shell { max-width: 420px; margin: 56px auto; text-align: center; padding: 28px 24px; position: relative; }
    .login-lang { position: absolute; top: 14px; right: 14px; }
    .login-brand { display: inline-flex; align-items: center; justify-content: center; gap: 12px; margin: 8px 0 14px; }
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
      <div class="login-lang lang-toggle">
        <button data-lang="ru" onclick="setLang('ru')">RU</button>
        <button data-lang="en" onclick="setLang('en')">EN</button>
      </div>
      <div class="login-brand">
        <img src="/assets/favicon.svg" alt="LocuGard" />
        <div class="login-wordmark"><span>locu</span><span>gard</span></div>
      </div>
      <p class="sub" data-i18n="login_sub"></p>
      <button class="primary" id="btnLogin" onclick="doLogin()" data-i18n="btn_sign_in"></button>
      <p class="sub hidden" style="margin-top:12px;font-size:12px;color:var(--warning)" id="secHint"></p>
    </div>

    <div id="viewApp" class="hidden">
      <header class="topbar">
        <div class="brand">
          <img class="brand-logo" src="/assets/favicon.svg" alt="LocuGard" />
          <div>
            <h1 id="hdrName">LocuGard</h1>
            <small id="hdrSub"></small>
          </div>
        </div>
        <div class="row">
          <span class="pill accent" id="pillRole">role</span>
          <span class="pill ok" id="pillMode"></span>
          <span class="pill" id="pillZone">LAN</span>
          <div class="lang-toggle">
            <button data-lang="ru" onclick="setLang('ru')">RU</button>
            <button data-lang="en" onclick="setLang('en')">EN</button>
          </div>
          <button onclick="doReauth()" data-i18n="btn_reauth"></button>
          <button class="danger" onclick="doLogout()" data-i18n="btn_sign_out"></button>
        </div>
      </header>

      <div id="csrfNotice" class="notice hidden">
        <span data-i18n="csrf_reload_notice"></span>
        <button onclick="doLogin()" style="margin-left:6px" data-i18n="btn_confirm_passkey"></button>
      </div>

      <nav class="tabs">
        <button class="tab active" data-tab="session" onclick="switchTab('session')" data-i18n="tab_session"></button>
        <button class="tab" data-tab="devices" onclick="switchTab('devices')" data-i18n="tab_devices"></button>
        <button class="tab" data-tab="actions" onclick="switchTab('actions')" data-i18n="tab_actions"></button>
        <button class="tab" data-tab="recovery" onclick="switchTab('recovery')" data-i18n="tab_recovery"></button>
      </nav>

      <section id="tab-session" class="card">
        <h2 data-i18n="session_title"></h2>
        <p class="sub" data-i18n="session_sub"></p>
        <div class="grid-2" id="sessionGrid"></div>
      </section>

      <section id="tab-devices" class="hidden">
        <div class="card">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2 data-i18n="devices_title"></h2>
              <p class="sub" style="margin-bottom:0" data-i18n="devices_sub"></p>
            </div>
            <button onclick="loadDevices()" data-i18n="btn_refresh"></button>
          </div>
          <div class="list" id="devicesList"></div>
        </div>

        <div class="card" id="ownerEnrollCard">
          <h2 data-i18n="enroll_title"></h2>
          <p class="sub" data-i18n="enroll_sub"></p>
          <div class="row">
            <input id="enrollTarget" style="max-width:300px" data-i18n-placeholder="enroll_target_ph" />
            <button class="primary" onclick="doCreateEnrollment()" data-i18n="btn_create_enroll"></button>
          </div>
          <div id="enrollResult" class="hidden" style="margin-top:14px">
            <div class="codebox" id="enrollBox"></div>
            <div class="row" style="margin-top:8px">
              <button onclick="copyText(document.getElementById('enrollBox').textContent)" data-i18n="btn_copy_json"></button>
            </div>
          </div>
        </div>

        <div class="card" id="ownerPendingCard">
          <div class="row" style="justify-content:space-between;margin-bottom:8px">
            <div>
              <h2 data-i18n="pending_title"></h2>
              <p class="sub" style="margin-bottom:0" data-i18n="pending_sub"></p>
            </div>
            <button onclick="loadPending()" data-i18n="btn_refresh"></button>
          </div>
          <div class="list" id="pendingList"></div>
        </div>
      </section>

      <section id="tab-actions" class="card hidden">
        <h2 data-i18n="actions_title"></h2>
        <p class="sub" data-i18n="actions_sub"></p>
        <div class="grid-2" style="margin-bottom:12px">
          <div>
            <label style="font-size:12px;color:var(--muted)" data-i18n="lbl_action_target"></label>
            <input id="actTarget" value="demo-target" />
          </div>
          <div>
            <label style="font-size:12px;color:var(--muted)" data-i18n="lbl_action_note"></label>
            <input id="actNote" data-i18n-placeholder="ph_action_note" />
          </div>
        </div>
        <button class="primary" onclick="doDangerReq()" data-i18n="btn_req_action"></button>

        <div id="approvalCard" class="hidden" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border)">
          <div class="kv" style="margin-bottom:10px">
            <label data-i18n="lbl_description"></label>
            <div class="val" id="apprDesc" style="font-family:var(--sans)"></div>
          </div>
          <div class="kv" style="margin-bottom:12px">
            <label>Action Digest (SHA-256)</label>
            <div class="val" id="apprDigest"></div>
          </div>
          <div class="row">
            <button class="primary" onclick="doDangerConf()" data-i18n="btn_confirm_exec"></button>
            <button onclick="clearApproval()" data-i18n="btn_reset"></button>
          </div>
        </div>
      </section>

      <section id="tab-recovery" class="card hidden">
        <h2 data-i18n="recovery_title"></h2>
        <p class="sub" data-i18n="recovery_sub"></p>
        <button class="primary" onclick="doGenRecovery()" data-i18n="btn_gen_recovery"></button>
        <div id="recoveryWrap" class="hidden">
          <div class="codes-grid" id="recoveryGrid"></div>
          <div class="row">
            <button onclick="copyRecovery()" data-i18n="btn_copy_all"></button>
            <button onclick="downloadRecovery()" data-i18n="btn_download_txt"></button>
          </div>
        </div>
      </section>
    </div>
  </div>
  <div id="toast" class="toast hidden"></div>

  <script>
    const I18N = {
      ru: {
        page_title: "LocuGard — Управление доступом",
        login_sub: "Используйте Passkey, биометрию или ключ безопасности.",
        btn_sign_in: "Войти",
        https_required: "Для входа по Passkey требуется HTTPS.",
        hdr_device: "Устройство",
        mode_prefix: "Режим",
        zone_lan: "LAN",
        zone_outside: "Вне LAN",
        btn_reauth: "Обновить личность",
        btn_sign_out: "Выйти",
        csrf_reload_notice: "Страница была перезагружена — для изменяющих операций подтвердите вход:",
        btn_confirm_passkey: "Подтвердить Passkey",
        tab_session: "Сессия",
        tab_devices: "Устройства",
        tab_actions: "Опасные действия",
        tab_recovery: "Recovery-коды",
        session_title: "Текущая сессия",
        session_sub: "Контекст проверен сервером по криптографической связке аккаунт ↔ устройство ↔ ключ.",
        kv_account_id: "Account ID",
        kv_name: "Имя",
        kv_role: "Роль",
        kv_device_id: "Device ID",
        kv_zone: "Зона сети",
        kv_mode: "Эффективный режим",
        devices_title: "Зарегистрированные устройства",
        devices_sub: "Отзыв немедленно завершает все сессии и refresh-цепочки устройства.",
        btn_refresh: "Обновить",
        devices_empty: "Устройств нет",
        hw_key: "Аппаратный ключ",
        sw_key: "Программный / Passkey",
        badge_current: "текущее",
        active_sessions: "активных сессий",
        btn_revoke: "Отозвать",
        confirm_revoke: "Отозвать устройство {id} и немедленно завершить все его сессии?",
        enroll_title: "Добавить новое устройство",
        enroll_sub: "Создаёт одноразовый код регистрации (TTL 5 минут) для нового браузера или нативного приложения.",
        enroll_target_ph: "account_id (пусто = текущий аккаунт)",
        btn_create_enroll: "Создать код регистрации",
        btn_copy_json: "Скопировать JSON",
        pending_title: "Ожидающие заявки на регистрацию",
        pending_sub: "Сверьте отпечаток ключа (key_fingerprint) перед одобрением.",
        pending_empty: "Ожидающих заявок нет",
        lbl_fingerprint: "Отпечаток",
        btn_approve: "Одобрить",
        actions_title: "Опасные действия (Permissions)",
        actions_sub: "Свежая проверка личности, неизменяемый action_digest и повторная проверка прав при исполнении.",
        lbl_action_target: "Цель действия",
        lbl_action_note: "Комментарий",
        ph_action_note: "причина операции",
        btn_req_action: "Запросить опасное действие",
        lbl_description: "Описание",
        btn_confirm_exec: "Подтвердить и выполнить",
        btn_reset: "Сбросить",
        recovery_title: "Офлайн Recovery-коды",
        recovery_sub: "Одноразовый запасной путь для владельца. Новый выпуск отзывает прежний набор; коды показываются один раз.",
        btn_gen_recovery: "Сгенерировать 10 recovery-кодов",
        btn_copy_all: "Скопировать все",
        btn_download_txt: "Скачать .txt",
        recovery_file_header: "LocuGard Recovery Codes (хранить офлайн)",
        t_copied: "Скопировано в буфер обмена",
        t_copy_err: "Не удалось скопировать",
        t_login_ok: "Вход выполнен",
        t_login_err: "Ошибка входа",
        t_reauth_ok: "Личность повторно подтверждена",
        t_reauth_err: "Ошибка подтверждения",
        t_logout_ok: "Сессия завершена",
        t_logout_err: "Ошибка выхода",
        t_devices_err: "Не удалось загрузить устройства",
        t_revoked: "Устройство отозвано",
        t_revoke_err: "Ошибка отзыва",
        t_enroll_ok: "Одноразовый код регистрации создан (TTL 5 мин)",
        t_enroll_err: "Ошибка создания кода",
        t_pending_err: "Не удалось загрузить заявки",
        t_approved: "Устройство одобрено и активировано",
        t_approve_err: "Ошибка одобрения",
        t_action_req_ok: "Заявка создана — подтвердите действие в течение 120 с",
        t_action_denied: "Отклонено",
        t_action_done: "Выполнено",
        t_action_err: "Ошибка выполнения",
        t_recovery_ok: "Выпущен новый набор recovery-кодов",
        t_recovery_err: "Ошибка выпуска recovery-кодов",
        err_codes: {
          authentication_failed: "Не удалось подтвердить ключ",
          fresh_verification_required: "Требуется свежее подтверждение личности (нажмите «Обновить личность»)",
          owner_required: "Доступно только владельцу (owner)",
          invalid_origin: "Недопустимый источник запроса (Origin)",
          csrf_failed: "Ошибка CSRF-токена — обновите вход",
          rate_limited: "Слишком много попыток, попробуйте позже",
          hardware_key_required: "В текущем режиме требуется аппаратный ключ",
          outside_allowed_network: "Доступ вне разрешённой локальной сети запрещён",
          new_devices_forbidden_in_mode_4: "В режиме 4 добавление новых устройств запрещено",
          approval_expired: "Срок подтверждения истёк",
          policy_changed: "Политика безопасности изменилась — повторите запрос",
          session_invalid_or_revoked: "Сессия недействительна или отозвана"
        }
      },
      en: {
        page_title: "LocuGard — Access Control",
        login_sub: "Use your Passkey, biometrics, or security key.",
        btn_sign_in: "Sign in",
        https_required: "HTTPS is required for Passkey sign-in.",
        hdr_device: "Device",
        mode_prefix: "Mode",
        zone_lan: "LAN",
        zone_outside: "Outside LAN",
        btn_reauth: "Step-up Reauth",
        btn_sign_out: "Sign Out",
        csrf_reload_notice: "Page was reloaded — re-confirm your Passkey for mutating actions:",
        btn_confirm_passkey: "Confirm Passkey",
        tab_session: "Session",
        tab_devices: "Devices",
        tab_actions: "Dangerous Actions",
        tab_recovery: "Recovery Codes",
        session_title: "Current Session",
        session_sub: "Context verified by the server via cryptographic account ↔ device ↔ key binding.",
        kv_account_id: "Account ID",
        kv_name: "Display Name",
        kv_role: "Role",
        kv_device_id: "Device ID",
        kv_zone: "Network Zone",
        kv_mode: "Effective Mode",
        devices_title: "Registered Devices",
        devices_sub: "Revoking a device immediately terminates all its sessions and refresh chains.",
        btn_refresh: "Refresh",
        devices_empty: "No devices found",
        hw_key: "Hardware-bound key",
        sw_key: "Software / Passkey",
        badge_current: "current",
        active_sessions: "active sessions",
        btn_revoke: "Revoke",
        confirm_revoke: "Revoke device {id} and immediately terminate all its sessions?",
        enroll_title: "Enroll New Device",
        enroll_sub: "Creates a one-time enrollment code (5 min TTL) for a new browser or native app.",
        enroll_target_ph: "account_id (empty = current account)",
        btn_create_enroll: "Create Enrollment Code",
        btn_copy_json: "Copy JSON",
        pending_title: "Pending Registrations",
        pending_sub: "Verify the key fingerprint before approving.",
        pending_empty: "No pending registrations",
        lbl_fingerprint: "Fingerprint",
        btn_approve: "Approve",
        actions_title: "Dangerous Actions (Permissions)",
        actions_sub: "Fresh identity verification, immutable action_digest, and live re-check at execution time.",
        lbl_action_target: "Action Target",
        lbl_action_note: "Note",
        ph_action_note: "reason for operation",
        btn_req_action: "Request Dangerous Action",
        lbl_description: "Description",
        btn_confirm_exec: "Confirm & Execute",
        btn_reset: "Reset",
        recovery_title: "Offline Recovery Codes",
        recovery_sub: "One-time emergency fallback for owners. Generating a new set revokes the previous one; codes are shown once.",
        btn_gen_recovery: "Generate 10 Recovery Codes",
        btn_copy_all: "Copy All",
        btn_download_txt: "Download .txt",
        recovery_file_header: "LocuGard Recovery Codes (store offline)",
        t_copied: "Copied to clipboard",
        t_copy_err: "Failed to copy",
        t_login_ok: "Signed in",
        t_login_err: "Sign-in failed",
        t_reauth_ok: "Identity re-verified",
        t_reauth_err: "Re-verification failed",
        t_logout_ok: "Signed out",
        t_logout_err: "Sign-out failed",
        t_devices_err: "Failed to load devices",
        t_revoked: "Device revoked",
        t_revoke_err: "Revocation failed",
        t_enroll_ok: "One-time enrollment code created (5 min TTL)",
        t_enroll_err: "Failed to create enrollment code",
        t_pending_err: "Failed to load pending requests",
        t_approved: "Device approved and activated",
        t_approve_err: "Approval failed",
        t_action_req_ok: "Approval requested — confirm within 120 s",
        t_action_denied: "Denied",
        t_action_done: "Executed",
        t_action_err: "Execution failed",
        t_recovery_ok: "New recovery code set generated",
        t_recovery_err: "Failed to generate recovery codes",
        err_codes: {
          authentication_failed: "Authentication failed",
          fresh_verification_required: "Fresh identity verification required (click Step-up Reauth)",
          owner_required: "Owner role required",
          invalid_origin: "Invalid request Origin",
          csrf_failed: "CSRF check failed — please sign in again",
          rate_limited: "Too many attempts, please wait",
          hardware_key_required: "Hardware-bound key required in this mode",
          outside_allowed_network: "Access outside allowed LAN is denied",
          new_devices_forbidden_in_mode_4: "Enrolling new devices is disabled in Mode 4",
          approval_expired: "Approval expired",
          policy_changed: "Security policy changed — please retry",
          session_invalid_or_revoked: "Session is invalid or revoked"
        }
      }
    };

    function detectInitialLang() {
      const qp = new URLSearchParams(window.location.search).get("lang");
      if (qp === "ru" || qp === "en") return qp;
      const htmlLang = (document.documentElement.lang || "").toLowerCase();
      if (htmlLang === "ru" || htmlLang === "en") return htmlLang;
      const nav = (navigator.language || "en").toLowerCase();
      return nav.startsWith("ru") ? "ru" : "en";
    }

    let lang = detectInitialLang();
    let csrf = "";
    let profile = null;
    let lastApproval = null;
    let lastRecoveryCodes = [];
    let activeTab = "session";

    const $ = (id) => document.getElementById(id);
    const t = (key) => (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key;
    const trErr = (code) => (I18N[lang] && I18N[lang].err_codes && I18N[lang].err_codes[code]) || code;
    const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

    function applyI18n() {
      document.documentElement.lang = lang;
      document.title = t("page_title");
      document.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
      document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
      document.querySelectorAll(".lang-toggle button").forEach(b => b.classList.toggle("active", b.dataset.lang === lang));
      if (!window.isSecureContext) $("secHint").textContent = t("https_required");
      renderProfile();
      if (profile && activeTab === "devices") {
        loadDevices();
        if (profile.role === "owner") loadPending();
      }
    }

    function setLang(next) {
      if (next !== "ru" && next !== "en") return;
      lang = next;
      const u = new URL(window.location.href);
      u.searchParams.set("lang", lang);
      window.history.replaceState({}, "", u.toString());
      applyI18n();
    }

    let toastTimer = null;
    function toast(msg, kind = "ok") {
      const el = $("toast");
      el.textContent = msg;
      el.className = "toast " + kind;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => el.classList.add("hidden"), 4200);
    }

    function copyText(text) {
      navigator.clipboard.writeText(text).then(() => toast(t("t_copied"))).catch(() => toast(t("t_copy_err"), "err"));
    }

    function switchTab(name) {
      activeTab = name;
      document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
      ["session", "devices", "actions", "recovery"].forEach(tab => $("tab-" + tab).classList.toggle("hidden", tab !== name));
      if (name === "devices") { loadDevices(); if (profile && profile.role === "owner") loadPending(); }
    }

    function escapeHtml(s) {
      return s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
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
      $("hdrSub").textContent = t("hdr_device") + ": " + profile.device_id;
      $("pillRole").textContent = profile.role;
      $("pillMode").textContent = t("mode_prefix") + " " + profile.effective_mode;
      $("pillZone").textContent = profile.network_zone === "lan" ? t("zone_lan") : t("zone_outside");
      $("ownerEnrollCard").classList.toggle("hidden", profile.role !== "owner");
      $("ownerPendingCard").classList.toggle("hidden", profile.role !== "owner");

      const fields = [
        [t("kv_account_id"), profile.account_id],
        [t("kv_name"), profile.display_name || "—"],
        [t("kv_role"), profile.role],
        [t("kv_device_id"), profile.device_id],
        [t("kv_zone"), profile.network_zone],
        [t("kv_mode"), t("mode_prefix") + " " + profile.effective_mode]
      ];
      $("sessionGrid").innerHTML = fields.map(([k, v]) => `<div class="kv"><label>${escapeHtml(k)}</label><div class="val">${escapeHtml(String(v))}</div></div>`).join("");
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
        $("secHint").textContent = t("https_required");
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
        toast(t("t_login_ok"));
      } catch (e) {
        toast(t("t_login_err") + ": " + trErr(e.message), "err");
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
        toast(t("t_reauth_ok"));
      } catch (e) {
        toast(t("t_reauth_err") + ": " + trErr(e.message), "err");
      }
    }

    async function doLogout() {
      try {
        await api("/auth/logout", { method: "POST" });
        csrf = ""; profile = null; lastApproval = null; lastRecoveryCodes = [];
        renderProfile();
        toast(t("t_logout_ok"));
      } catch (e) {
        toast(t("t_logout_err") + ": " + trErr(e.message), "err");
      }
    }

    async function loadDevices() {
      try {
        const { devices } = await api("/api/devices");
        if (!devices.length) { $("devicesList").innerHTML = `<div class="empty">${escapeHtml(t("devices_empty"))}</div>`; return; }
        $("devicesList").innerHTML = devices.map(d => {
          const stClass = d.state === "active" ? "ok" : (d.state === "pending" ? "warn" : "danger");
          const hw = d.hardware_binding ? t("hw_key") : t("sw_key");
          const isCur = profile && d.device_id === profile.device_id;
          return `<div class="item">
            <div>
              <div class="row">
                <strong>${escapeHtml(d.display_name)}</strong>
                <span class="pill ${stClass}">${escapeHtml(d.state)}</span>
                ${isCur ? `<span class="pill accent">${escapeHtml(t("badge_current"))}</span>` : ''}
              </div>
              <div class="item-meta">${escapeHtml(d.device_id)} · ${escapeHtml(d.kind)} · ${escapeHtml(hw)} · ${escapeHtml(t("active_sessions"))}: ${d.active_sessions_count || 0}</div>
            </div>
            ${d.state !== "revoked" ? `<button class="danger" onclick="doRevokeDevice('${escapeHtml(d.device_id)}')">${escapeHtml(t("btn_revoke"))}</button>` : ''}
          </div>`;
        }).join("");
      } catch (e) {
        toast(t("t_devices_err") + ": " + trErr(e.message), "err");
      }
    }

    async function doRevokeDevice(deviceId) {
      if (!confirm(t("confirm_revoke").replace("{id}", deviceId))) return;
      try {
        await api("/api/devices/" + encodeURIComponent(deviceId) + "/revoke", { method: "POST" });
        toast(t("t_revoked"));
        if (profile && deviceId === profile.device_id) { csrf = ""; profile = null; renderProfile(); return; }
        loadDevices();
      } catch (e) {
        toast(t("t_revoke_err") + ": " + trErr(e.message), "err");
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
        toast(t("t_enroll_ok"));
      } catch (e) {
        toast(t("t_enroll_err") + ": " + trErr(e.message), "err");
      }
    }

    async function loadPending() {
      try {
        const { requests } = await api("/api/devices/registrations");
        if (!requests.length) { $("pendingList").innerHTML = `<div class="empty">${escapeHtml(t("pending_empty"))}</div>`; return; }
        $("pendingList").innerHTML = requests.map(r => `<div class="item">
          <div>
            <div class="row">
              <strong>${escapeHtml(r.device_name || r.device_id)}</strong>
              <span class="pill warn">${escapeHtml(r.requested_role)}</span>
              <span class="pill">${escapeHtml(r.device_kind || "device")}</span>
            </div>
            <div class="item-meta">ID: ${escapeHtml(r.request_id)} · ${escapeHtml(t("lbl_fingerprint"))}: ${escapeHtml(r.key_fingerprint)}</div>
          </div>
          <button class="primary" onclick="doApprove('${escapeHtml(r.request_id)}')">${escapeHtml(t("btn_approve"))}</button>
        </div>`).join("");
      } catch (e) {
        toast(t("t_pending_err") + ": " + trErr(e.message), "err");
      }
    }

    async function doApprove(requestId) {
      try {
        await api("/api/devices/registrations/" + encodeURIComponent(requestId) + "/approve", { method: "POST", body: "{}" });
        toast(t("t_approved"));
        loadPending(); loadDevices();
      } catch (e) {
        toast(t("t_approve_err") + ": " + trErr(e.message), "err");
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
        toast(t("t_action_req_ok"));
      } catch (e) {
        toast(t("t_action_denied") + ": " + trErr(e.message), "err");
      }
    }

    async function doDangerConf() {
      if (!lastApproval) return;
      try {
        const res = await api("/api/protected/dangerous-action/confirm", {
          method: "POST",
          body: JSON.stringify({ approval_id: lastApproval.approval_id, action_digest: lastApproval.action_digest })
        });
        toast(t("t_action_done") + ": " + (res.status || "ok"));
        clearApproval();
      } catch (e) {
        toast(t("t_action_err") + ": " + trErr(e.message), "err");
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
        toast(t("t_recovery_ok") + " (" + lastRecoveryCodes.length + ")");
      } catch (e) {
        toast(t("t_recovery_err") + ": " + trErr(e.message), "err");
      }
    }

    function copyRecovery() { copyText(lastRecoveryCodes.join("\\n")); }
    function downloadRecovery() {
      const blob = new Blob([t("recovery_file_header") + "\\n\\n" + lastRecoveryCodes.join("\\n") + "\\n"], { type: "text/plain;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "locugard-recovery-codes.txt";
      a.click();
      URL.revokeObjectURL(a.href);
    }

    applyI18n();
    checkSession();
  </script>
</body>
</html>
"""


def resolve_ui_lang(query_lang: str | None = None, accept_language: str | None = None) -> str:
    if query_lang:
        q = query_lang.strip().lower()
        if q.startswith("ru"):
            return "ru"
        if q.startswith("en"):
            return "en"
    if accept_language:
        al = accept_language.lower()
        ru_idx = al.find("ru")
        en_idx = al.find("en")
        if ru_idx != -1 and (en_idx == -1 or ru_idx < en_idx):
            return "ru"
    return "en"


def render_web_ui(lang: str = "en") -> str:
    resolved = "ru" if (lang or "").lower().startswith("ru") else "en"
    return WEB_UI_HTML.replace("__LOCUGARD_LANG__", resolved)
