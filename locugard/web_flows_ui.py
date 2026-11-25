"""Встроенные EN/RU страницы LocuGard для Device Pairing (/pair) и Browser SSO (/sso/authorize)."""
from __future__ import annotations

import json
from urllib.parse import urlparse


def _safe_json_script(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


PAIR_UI_HTML = """<!doctype html>
<html lang="__LOCUGARD_LANG__">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LocuGard — Pair Device</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml" />
  <link rel="icon" href="/favicon.ico" sizes="any" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
  <style>
    :root {
      color-scheme: dark light;
      --bg: #0c0f14; --surface: #141923; --surface-2: #1b2230;
      --border: rgba(255,255,255,0.09); --text: #edf1f7; --muted: #94a3b8;
      --accent: #0f766e; --accent-hover: #0d9488; --accent-soft: #2dd4bf;
      --success: #22c55e; --warning: #f59e0b; --danger: #ef4444;
      --radius: 12px; --shadow: 0 12px 32px rgba(0,0,0,0.35);
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f4f6fa; --surface: #ffffff; --surface-2: #f8fafc;
        --border: rgba(15,23,42,0.1); --text: #0f172a; --muted: #475569;
        --accent-soft: #0f766e; --shadow: 0 8px 24px rgba(15,23,42,0.08);
      }
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: var(--sans); background: var(--bg); color: var(--text); line-height: 1.5; min-height: 100vh; }
    .wrap { max-width: 500px; margin: 48px auto; padding: 0 20px 64px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; box-shadow: var(--shadow); position: relative; }
    .top-lang { position: absolute; top: 14px; right: 14px; display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--surface-2); }
    .top-lang button { border: 0; border-radius: 0; padding: 5px 9px; font-size: 12px; background: transparent; color: var(--muted); cursor: pointer; font-weight: 600; }
    .top-lang button.active { background: var(--accent); color: #fff; }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
    .brand img { width: 40px; height: 40px; border-radius: 10px; }
    .brand h1 { margin: 0; font-size: 19px; }
    .sub { color: var(--muted); font-size: 13.5px; margin: 0 0 16px; }
    .kv { background: var(--surface-2); border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px; margin-bottom: 10px; }
    .kv label { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
    .kv .val { font-family: var(--mono); font-size: 13px; margin-top: 2px; word-break: break-all; }
    label.fld { display: block; font-size: 12px; color: var(--muted); margin: 12px 0 4px; font-weight: 600; }
    input, select { font: inherit; font-size: 14px; padding: 9px 12px; border-radius: 9px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text); width: 100%; }
    input.code-input { font-family: var(--mono); font-size: 18px; letter-spacing: 0.12em; text-transform: uppercase; text-align: center; font-weight: 700; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; align-items: center; }
    button.btn { font: inherit; font-size: 13.5px; font-weight: 600; padding: 9px 15px; border-radius: 9px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text); cursor: pointer; }
    button.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.btn.primary:hover { background: var(--accent-hover); }
    button.btn.danger { background: rgba(239,68,68,0.14); border-color: rgba(239,68,68,0.4); color: #fca5a5; }
    @media (prefers-color-scheme: light) { button.btn.danger { color: #b91c1c; } }
    .hidden { display: none !important; }
    .msg { margin-top: 12px; font-size: 13px; }
    .msg.ok { color: var(--success); }
    .msg.err { color: var(--danger); }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="top-lang">
        <button data-lang="ru" onclick="setLang('ru')">RU</button>
        <button data-lang="en" onclick="setLang('en')">EN</button>
      </div>
      <div class="brand">
        <img src="/assets/favicon.svg" alt="LocuGard" />
        <h1 data-i18n="title"></h1>
      </div>

      <div id="stepLogin">
        <p class="sub" data-i18n="login_sub"></p>
        <button class="btn primary" style="width:100%" onclick="doLogin()" data-i18n="btn_sign_in"></button>
      </div>

      <div id="stepApprove" class="hidden">
        <p class="sub" data-i18n="approve_sub"></p>
        <div class="kv"><label data-i18n="lbl_device"></label><div class="val" id="pDevice" style="font-family:var(--sans);font-weight:600"></div></div>
        <div class="kv"><label data-i18n="lbl_fp"></label><div class="val" id="pFp"></div></div>
        <div class="kv"><label data-i18n="lbl_key_type"></label><div class="val" id="pHw" style="font-family:var(--sans)"></div></div>

        <label class="fld" data-i18n="lbl_account"></label>
        <select id="pAccount"></select>

        <label class="fld" data-i18n="lbl_code"></label>
        <input id="pCode" class="code-input" placeholder="XXXX-XXXX" autocomplete="off" />

        <div class="row">
          <button class="btn primary" onclick="doApprove()" data-i18n="btn_approve"></button>
          <button class="btn danger" onclick="doReject()" data-i18n="btn_reject"></button>
          <button class="btn" onclick="doReauth()" style="margin-left:auto" data-i18n="btn_reauth"></button>
        </div>
      </div>

      <div id="stepDone" class="hidden">
        <p class="sub" style="color:var(--success);font-weight:600" id="doneText"></p>
        <div class="row">
          <a href="/" class="btn primary" style="text-decoration:none" data-i18n="btn_home"></a>
        </div>
      </div>

      <div id="statusMsg" class="msg"></div>
    </div>
  </div>
  <script>
    const I18N = {
      ru: {
        title: "Привязка приложения",
        login_sub: "Подтвердите личность владельца с помощью Passkey, чтобы просмотреть и одобрить заявку приложения.",
        btn_sign_in: "Войти как владелец",
        approve_sub: "Сверьте имя устройства, отпечаток ключа и введите 8-значный проверочный код с экрана приложения.",
        lbl_device: "Устройство",
        lbl_fp: "Отпечаток ключа",
        lbl_key_type: "Тип ключа",
        hw_yes: "Аппаратное хранилище ОС (TPM / Keystore)",
        hw_no: "Программный ключ",
        lbl_account: "Привязать к аккаунту",
        lbl_code: "Проверочный код с экрана приложения",
        btn_approve: "Разрешить устройство",
        btn_reject: "Отклонить",
        btn_reauth: "Обновить Passkey",
        btn_home: "Открыть панель LocuGard",
        err_no_id: "Не указан параметр ?id= заявки.",
        err_code_empty: "Введите 8-значный код с экрана приложения.",
        done_approved: "Устройство разрешено! Можете вернуться в приложение — вход завершится автоматически.",
        done_rejected: "Заявка отклонена.",
        reauth_ok: "Личность подтверждена — теперь нажмите «Разрешить устройство»."
      },
      en: {
        title: "Pair Native App",
        login_sub: "Sign in as the owner with your Passkey to review and approve this application pairing request.",
        btn_sign_in: "Sign in as Owner",
        approve_sub: "Verify the device name, key fingerprint, and enter the 8-character code shown in the app.",
        lbl_device: "Device",
        lbl_fp: "Key Fingerprint",
        lbl_key_type: "Key Type",
        hw_yes: "OS Hardware Keystore (TPM / Keystore)",
        hw_no: "Software Key",
        lbl_account: "Bind to Account",
        lbl_code: "Verification Code from App Screen",
        btn_approve: "Approve Device",
        btn_reject: "Reject",
        btn_reauth: "Refresh Passkey",
        btn_home: "Open LocuGard Dashboard",
        err_no_id: "Missing ?id= pairing parameter.",
        err_code_empty: "Enter the 8-character code shown in the app.",
        done_approved: "Device approved! Return to the app — sign-in will complete automatically.",
        done_rejected: "Pairing request rejected.",
        reauth_ok: "Identity re-verified — click Approve Device now."
      }
    };
    let lang = (new URLSearchParams(location.search).get("lang") || document.documentElement.lang || "en").toLowerCase().startsWith("ru") ? "ru" : "en";
    const pairId = (new URLSearchParams(location.search).get("id") || "").trim();
    let csrf = "";
    const $ = id => document.getElementById(id);
    const t = k => I18N[lang][k] || I18N.en[k] || k;
    const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');

    function applyI18n() {
      document.documentElement.lang = lang;
      document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = t(el.dataset.i18n));
      document.querySelectorAll(".top-lang button").forEach(b => b.classList.toggle("active", b.dataset.lang === lang));
    }
    function setLang(l) {
      lang = l;
      const u = new URL(location.href); u.searchParams.set("lang", l); history.replaceState({}, "", u.toString());
      applyI18n();
    }
    function setMsg(text, kind) { const el = $("statusMsg"); el.textContent = text; el.className = "msg " + kind; }

    async function api(url, opts = {}) {
      const headers = Object.assign({}, opts.headers || {});
      if (opts.method && opts.method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
      if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const r = await fetch(url, Object.assign({}, opts, { headers }));
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
      return data;
    }

    async function doLogin() {
      setMsg("", "");
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
        await loadPairDetails(body.account_id);
      } catch (e) {
        setMsg(e.message || String(e), "err");
      }
    }

    async function doReauth() {
      setMsg("", "");
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
        setMsg(t("reauth_ok"), "ok");
      } catch (e) {
        setMsg(e.message || String(e), "err");
      }
    }

    async function loadPairDetails(defaultAccId) {
      if (!pairId) return setMsg(t("err_no_id"), "err");
      const info = await api("/api/devices/pairings/" + encodeURIComponent(pairId));
      if (info.state !== "pending_approval") {
        setMsg("Status: " + info.state, "err");
        return;
      }
      const { accounts } = await api("/api/accounts");
      $("pDevice").textContent = info.device_name;
      $("pFp").textContent = info.key_fingerprint || "—";
      $("pHw").textContent = info.hardware_binding ? t("hw_yes") : t("hw_no");
      $("pAccount").innerHTML = accounts.map(a =>
        `<option value="${a.account_id}" ${a.account_id === defaultAccId ? "selected" : ""}>${a.display_name} (${a.role})</option>`
      ).join("");
      $("stepLogin").classList.add("hidden");
      $("stepApprove").classList.remove("hidden");
    }

    async function doApprove() {
      const code = $("pCode").value.trim();
      if (!code) return setMsg(t("err_code_empty"), "err");
      setMsg("", "");
      try {
        await api("/api/devices/pairings/" + encodeURIComponent(pairId) + "/approve", {
          method: "POST",
          body: JSON.stringify({ user_code: code, target_account_id: $("pAccount").value })
        });
        $("stepApprove").classList.add("hidden");
        $("doneText").textContent = t("done_approved");
        $("stepDone").classList.remove("hidden");
      } catch (e) {
        setMsg(e.message || String(e), "err");
      }
    }

    async function doReject() {
      setMsg("", "");
      try {
        await api("/api/devices/pairings/" + encodeURIComponent(pairId) + "/reject", { method: "POST", body: "{}" });
        $("stepApprove").classList.add("hidden");
        $("doneText").textContent = t("done_rejected");
        $("stepDone").classList.remove("hidden");
      } catch (e) {
        setMsg(e.message || String(e), "err");
      }
    }

    applyI18n();
    if (!pairId) setMsg(t("err_no_id"), "err");
  </script>
</body>
</html>
"""


SSO_UI_HTML = """<!doctype html>
<html lang="__LOCUGARD_LANG__">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LocuGard — Sign In</title>
  <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml" />
  <link rel="icon" href="/favicon.ico" sizes="any" />
  <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png" />
  <style>
    :root {
      color-scheme: dark light;
      --bg: #0c0f14; --surface: #141923; --surface-2: #1b2230;
      --border: rgba(255,255,255,0.09); --text: #edf1f7; --muted: #94a3b8;
      --accent: #0f766e; --accent-hover: #0d9488; --accent-soft: #2dd4bf;
      --danger: #ef4444; --radius: 12px; --shadow: 0 12px 32px rgba(0,0,0,0.35);
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      --sans: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f4f6fa; --surface: #ffffff; --surface-2: #f8fafc;
        --border: rgba(15,23,42,0.1); --text: #0f172a; --muted: #475569;
        --accent-soft: #0f766e; --shadow: 0 8px 24px rgba(15,23,42,0.08);
      }
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: var(--sans); background: var(--bg); color: var(--text); line-height: 1.5; min-height: 100vh; }
    .wrap { max-width: 440px; margin: 56px auto; padding: 0 20px 64px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 28px 24px; box-shadow: var(--shadow); text-align: center; position: relative; }
    .top-lang { position: absolute; top: 14px; right: 14px; display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: var(--surface-2); }
    .top-lang button { border: 0; border-radius: 0; padding: 5px 9px; font-size: 12px; background: transparent; color: var(--muted); cursor: pointer; font-weight: 600; }
    .top-lang button.active { background: var(--accent); color: #fff; }
    .brand { display: inline-flex; align-items: center; gap: 10px; margin: 8px 0 14px; }
    .brand img { width: 42px; height: 42px; border-radius: 11px; }
    .wordmark { font-size: 24px; font-weight: 700; letter-spacing: -0.04em; }
    .wordmark span:first-child { color: var(--accent-soft); }
    h2 { margin: 0 0 8px; font-size: 18px; }
    .sub { color: var(--muted); font-size: 13.5px; margin: 0 0 16px; }
    .pill { display: inline-block; font-family: var(--mono); font-size: 12px; padding: 4px 10px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); color: var(--muted); margin-bottom: 16px; }
    .acct { background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-bottom: 16px; text-align: left; }
    .acct strong { display: block; font-size: 14.5px; }
    .acct small { color: var(--muted); font-family: var(--mono); font-size: 12px; }
    .row { display: flex; gap: 8px; flex-direction: column; }
    button.btn { font: inherit; font-size: 14.5px; font-weight: 600; padding: 10px 16px; border-radius: 9px; border: 1px solid var(--border); background: var(--surface-2); color: var(--text); cursor: pointer; width: 100%; }
    button.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.btn.primary:hover { background: var(--accent-hover); }
    .hidden { display: none !important; }
    .err { color: var(--danger); font-size: 13px; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="top-lang">
        <button data-lang="ru" onclick="setLang('ru')">RU</button>
        <button data-lang="en" onclick="setLang('en')">EN</button>
      </div>
      <div class="brand">
        <img src="/assets/favicon.svg" alt="LocuGard" />
        <div class="wordmark"><span>locu</span><span>gard</span></div>
      </div>
      <h2 id="ssoTitle"></h2>
      <div class="pill" id="ssoOriginPill"></div>

      <div id="stepSignIn">
        <p class="sub" data-i18n="signin_sub"></p>
        <div class="row">
          <button class="btn primary" onclick="doSignIn()" data-i18n="btn_signin"></button>
          <button class="btn" onclick="doCancel()" data-i18n="btn_cancel"></button>
        </div>
      </div>

      <div id="stepConsent" class="hidden">
        <div class="acct">
          <strong id="acctName"></strong>
          <small id="acctMeta"></small>
        </div>
        <div class="row">
          <button class="btn primary" onclick="doApprove()" data-i18n="btn_continue"></button>
          <button class="btn" onclick="doCancel()" data-i18n="btn_cancel"></button>
        </div>
      </div>

      <div id="errBox" class="err"></div>
    </div>
  </div>
  <script type="application/json" id="ssoParams">__SSO_PARAMS_JSON__</script>
  <script>
    const PARAMS = JSON.parse(document.getElementById("ssoParams").textContent);
    const I18N = {
      ru: {
        title_fmt: "Вход в {app}",
        signin_sub: "Подтвердите личность с помощью Passkey, чтобы продолжить.",
        btn_signin: "Войти с Passkey",
        btn_continue: "Продолжить",
        btn_cancel: "Отмена"
      },
      en: {
        title_fmt: "Sign in to {app}",
        signin_sub: "Verify your identity with your Passkey to continue.",
        btn_signin: "Sign in with Passkey",
        btn_continue: "Continue",
        btn_cancel: "Cancel"
      }
    };
    let lang = (new URLSearchParams(location.search).get("lang") || document.documentElement.lang || "en").toLowerCase().startsWith("ru") ? "ru" : "en";
    let csrf = "";
    const $ = id => document.getElementById(id);
    const t = k => I18N[lang][k] || I18N.en[k] || k;
    const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');

    function applyI18n() {
      document.documentElement.lang = lang;
      $("ssoTitle").textContent = t("title_fmt").replace("{app}", PARAMS.client_display_name);
      $("ssoOriginPill").textContent = PARAMS.target_origin;
      document.querySelectorAll("[data-i18n]").forEach(el => el.textContent = t(el.dataset.i18n));
      document.querySelectorAll(".top-lang button").forEach(b => b.classList.toggle("active", b.dataset.lang === lang));
    }
    function setLang(l) {
      lang = l;
      const u = new URL(location.href); u.searchParams.set("lang", l); history.replaceState({}, "", u.toString());
      applyI18n();
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

    async function doSignIn() {
      $("errBox").textContent = "";
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
        const prof = await api("/api/protected/profile");
        $("acctName").textContent = prof.display_name || prof.account_id;
        $("acctMeta").textContent = prof.role + " · " + prof.device_id;
        $("stepSignIn").classList.add("hidden");
        $("stepConsent").classList.remove("hidden");
      } catch (e) {
        $("errBox").textContent = e.message || String(e);
      }
    }

    async function doApprove() {
      $("errBox").textContent = "";
      try {
        const res = await api("/sso/approve", {
          method: "POST",
          body: JSON.stringify({
            client_id: PARAMS.client_id,
            redirect_uri: PARAMS.redirect_uri,
            code_challenge: PARAMS.code_challenge,
            code_challenge_method: "S256",
            state: PARAMS.state || ""
          })
        });
        window.location.href = res.redirect_url;
      } catch (e) {
        $("errBox").textContent = e.message || String(e);
      }
    }

    function doCancel() {
      const u = new URL(PARAMS.redirect_uri);
      u.searchParams.set("error", "access_denied");
      if (PARAMS.state) u.searchParams.set("state", PARAMS.state);
      window.location.href = u.toString();
    }

    applyI18n();
  </script>
</body>
</html>
"""


def render_pair_ui(lang: str = "en") -> str:
    resolved = "ru" if (lang or "").lower().startswith("ru") else "en"
    return PAIR_UI_HTML.replace("__LOCUGARD_LANG__", resolved)


def render_sso_ui(
    lang: str = "en",
    *,
    client_id: str,
    client_display_name: str,
    redirect_uri: str,
    code_challenge: str,
    state_param: str = "",
) -> str:
    resolved = "ru" if (lang or "").lower().startswith("ru") else "en"
    parsed = urlparse(redirect_uri)
    target_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else redirect_uri
    payload = _safe_json_script({
        "client_id": client_id,
        "client_display_name": client_display_name or client_id,
        "redirect_uri": redirect_uri,
        "target_origin": target_origin,
        "code_challenge": code_challenge,
        "state": state_param,
    })
    return SSO_UI_HTML.replace("__LOCUGARD_LANG__", resolved).replace("__SSO_PARAMS_JSON__", payload)
