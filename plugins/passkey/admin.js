// pb-passkey: passkeys on PocketBase's dashboard. Served by admin.go (plugins/passkey).
// Plain JS, no build step. Two jobs:
//   - on /_/ : "Sign in with passkey" under the login form, and a "Passkeys" button once signed in;
//   - on /_/passkeys : list, add and remove the signed-in superuser's passkeys.
// The dashboard keeps its session in localStorage "__pb_superusers__<path>" as {token, record}
// (ui/src/pb.js); this script reads and writes the same entry. Password login is untouched.

const BASE = location.pathname.replace(/\/passkeys\/?$/, "/").replace(/\/$/, ""); // "/_"
const KEY = "__pb_superusers__" + BASE;
const ON_MANAGE = /\/passkeys\/?$/.test(location.pathname);

const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "")), (c) => c.charCodeAt(0));
const enc = (b) => (b ? btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null);
function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "style") n.setAttribute("style", v);
    else if (k === "ariaHidden" || k === "role") n.setAttribute(k === "ariaHidden" ? "aria-hidden" : k, v);
    else n[k] = v;
  }
  n.append(...kids);
  return n;
}

function session() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "null");
  } catch {
    return null;
  }
}

async function api(method, path, body) {
  const s = session();
  const r = await fetch(path, {
    method,
    headers: { "content-type": "application/json", ...(s?.token ? { authorization: s.token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = r.status === 204 ? {} : await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.message || "HTTP " + r.status), { status: r.status });
  return j;
}

function webauthnError(x) {
  if (x?.name === "NotAllowedError" || x?.name === "AbortError") return new Error("Cancelled, or the fingerprint / face / PIN check did not pass.");
  if (x?.name === "SecurityError") return new Error("Passkeys do not work at this address. Open the configured https address, or localhost.");
  if (x?.name === "InvalidStateError") return new Error("This authenticator already holds a passkey for this account.");
  if (x?.status === 503) return new Error("Passkeys are not configured on this server.");
  return x instanceof Error ? x : new Error(String(x));
}

// --- sign in (login page) ----------------------------------------------------------------------

async function signIn() {
  let begun, cred;
  try {
    begun = await api("POST", "/api/passkey/login/begin");
    const pk = begun.options.publicKey;
    cred = await navigator.credentials.get({
      publicKey: { ...pk, challenge: dec(pk.challenge), allowCredentials: pk.allowCredentials?.map((c) => ({ ...c, id: dec(c.id) })) },
    });
  } catch (x) {
    throw webauthnError(x);
  }
  const r = cred.response;
  let j;
  try {
    j = await api("POST", `/api/passkey/login/finish?sid=${encodeURIComponent(begun.sid)}&only=_superusers`, {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: enc(r.clientDataJSON), authenticatorData: enc(r.authenticatorData),
        signature: enc(r.signature), userHandle: enc(r.userHandle),
      },
    });
  } catch (x) {
    if (x.status === 403) throw new Error("This passkey is not a superuser's. The dashboard takes superuser passkeys only.");
    throw new Error("This passkey could not sign in. Use the password.");
  }
  localStorage.setItem(KEY, JSON.stringify({ token: j.token, record: j.record }));
  location.hash = "#/";
  location.reload();
}

function loginButton(form) {
  const msg = el("div", { className: "txt-center txt-sm txt-danger m-t-5", role: "alert" });
  const btn = el("button", { type: "button", className: "btn lg block secondary" },
    el("i", { className: "ri-fingerprint-line", ariaHidden: "true" }),
    el("span", { className: "txt" }, "Sign in with passkey"));
  btn.onclick = async () => {
    btn.disabled = true;
    btn.classList.add("loading");
    msg.textContent = "";
    try {
      await signIn();
    } catch (x) {
      msg.textContent = x.message;
    }
    btn.disabled = false;
    btn.classList.remove("loading");
  };
  const box = el("div", { id: "pb-passkey-login", className: "block m-t-sm" }, btn, msg);
  form.after(box);
}

// "Passkeys" button on every signed-in dashboard page, bottom left.
function manageLink() {
  const a = el("a", {
    id: "pb-passkey-link", href: "./passkeys", className: "btn sm secondary",
    title: "Your passkeys: sign in with a fingerprint, face or security key",
    style: "position:fixed;left:12px;bottom:12px;z-index:99;",
  }, el("i", { className: "ri-fingerprint-line", ariaHidden: "true" }), el("span", { className: "txt" }, "Passkeys"));
  document.body.append(a);
}

function watchDashboard() {
  const check = () => {
    // the dashboard re-renders its forms (MFA step, route change): keep the button beside the live one
    const form = document.querySelector("form.auth-with-password-form");
    const box = document.getElementById("pb-passkey-login");
    if (form && !(box && box.previousElementSibling === form)) {
      box?.remove();
      loginButton(form);
    } else if (!form && box) box.remove();
    const link = document.getElementById("pb-passkey-link");
    const signedIn = !!session()?.token && !location.hash.startsWith("#/login");
    if (signedIn && !link) manageLink();
    if (!signedIn && link) link.remove();
  };
  new MutationObserver(check).observe(document.documentElement, { childList: true, subtree: true });
  addEventListener("hashchange", check);
  check();
}

// --- manage page (/_/passkeys) -----------------------------------------------------------------

async function addPasskey(name) {
  let begun, cred;
  try {
    begun = await api("POST", "/api/passkey/register/begin");
    const pk = begun.options.publicKey;
    cred = await navigator.credentials.create({
      publicKey: {
        ...pk, challenge: dec(pk.challenge), user: { ...pk.user, id: dec(pk.user.id) },
        excludeCredentials: pk.excludeCredentials?.map((c) => ({ ...c, id: dec(c.id) })),
      },
    });
  } catch (x) {
    throw webauthnError(x);
  }
  const r = cred.response;
  await api("POST", `/api/passkey/register/finish?sid=${encodeURIComponent(begun.sid)}&name=${encodeURIComponent(name)}`, {
    id: cred.id, rawId: enc(cred.rawId), type: cred.type,
    response: { clientDataJSON: enc(r.clientDataJSON), attestationObject: enc(r.attestationObject), transports: r.getTransports?.() },
  });
}

function guessName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android";
  if (/Mac/.test(ua)) return "Mac Touch ID";
  if (/Windows/.test(ua)) return "Windows Hello";
  return "passkey";
}

async function managePage(root) {
  document.title = "Passkeys - PocketBase";
  const s = session();
  const wrap = el("div", { className: "content", style: "max-width:560px;margin:40px auto;padding:0 20px;" });
  root.append(wrap);
  const back = el("a", { href: "./#/", className: "btn sm transparent secondary" },
    el("i", { className: "ri-arrow-left-line", ariaHidden: "true" }), el("span", { className: "txt" }, "Back to the dashboard"));
  wrap.append(back, el("h2", { className: "m-t-sm m-b-sm" }, "Passkeys"));
  if (!s?.token) {
    wrap.append(el("p", {}, "Sign in to the dashboard first, then come back here."));
    return;
  }
  wrap.append(el("p", { className: "txt-hint" },
    `Signed in as ${s.record?.email ?? "superuser"}. A passkey signs you in with your fingerprint, face, PIN or a security key. Your password keeps working.`));
  const msg = el("div", { className: "txt-sm m-t-5", role: "status" });
  const list = el("div", { className: "m-t-sm" });
  const name = el("input", { type: "text", value: guessName(), maxLength: 100, placeholder: "Name, e.g. MacBook Touch ID", ariaLabel: "Passkey name" });
  const add = el("button", { type: "button", className: "btn" },
    el("i", { className: "ri-add-line", ariaHidden: "true" }), el("span", { className: "txt" }, "Add a passkey"));
  wrap.append(el("div", { style: "display:flex;gap:10px;align-items:center" }, el("div", { className: "field", style: "flex:1;margin:0" }, name), add), msg, list);

  const say = (t, bad) => { msg.textContent = t; msg.className = "txt-sm m-t-5 " + (bad ? "txt-danger" : "txt-success"); };
  const render = async () => {
    list.textContent = "";
    let j;
    try {
      j = await api("GET", "/api/passkey");
    } catch (x) {
      say(x.status === 401 || x.status === 403 ? "Your dashboard session ended: sign in again." : x.message, true);
      return;
    }
    if (!j.configured) say("Passkeys are not configured on this server (RPID / origins).", true);
    if (!j.items.length) list.append(el("p", { className: "txt-hint" }, "No passkeys yet."));
    for (const it of j.items) {
      const del = el("button", { type: "button", className: "btn sm transparent secondary", title: "Remove" },
        el("i", { className: "ri-delete-bin-7-line", ariaHidden: "true" }));
      del.onclick = async () => {
        if (!confirm(`Remove the passkey "${it.name}"?`)) return;
        try {
          await api("DELETE", "/api/passkey/" + encodeURIComponent(it.id));
          say("Removed.");
        } catch (x) {
          say(x.message, true);
        }
        render();
      };
      const when = it.last_used ? "last used " + it.last_used.slice(0, 16) : "never used";
      list.append(el("div", { className: "flex", style: "display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--baseAlt2Color, #ddd)" },
        el("i", { className: "ri-fingerprint-line", ariaHidden: "true" }),
        el("div", { style: "flex:1" }, el("strong", {}, it.name), el("div", { className: "txt-hint txt-sm" }, `added ${it.created.slice(0, 16)}, ${when}`)),
        del));
    }
  };
  add.onclick = async () => {
    add.disabled = true;
    add.classList.add("loading");
    try {
      await addPasskey(name.value.trim() || guessName());
      say("Passkey added. Next time, use \"Sign in with passkey\" on the login page.");
    } catch (x) {
      say(x.message, true);
    }
    add.disabled = false;
    add.classList.remove("loading");
    render();
  };
  render();
}

// WebAuthn needs a secure context (https, or http://localhost): elsewhere the buttons would only fail.
const supported = window.isSecureContext && typeof window.PublicKeyCredential === "function";
if (ON_MANAGE) {
  const root = document.getElementById("pb-passkey-manage");
  if (supported) managePage(root);
  else root.append(el("p", { style: "margin:40px" }, "Passkeys need https (or http://localhost). Open this page at the server's https address."));
} else if (supported) {
  watchDashboard();
}
