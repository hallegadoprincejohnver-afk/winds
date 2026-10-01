export const CLIENT_SCRIPT = `(() => {
  const started = performance.now();
  const events = { pointer: 0, key: 0, focus: 0, hidden: 0, scriptAdded: 0 };
  const native = {
    pushState: history.pushState,
    replaceState: history.replaceState,
    appendChild: Node.prototype.appendChild,
    querySelector: Document.prototype.querySelector,
    querySelectorAll: Document.prototype.querySelectorAll,
    getElementById: Document.prototype.getElementById,
    fetch: window.fetch,
    xhrOpen: XMLHttpRequest.prototype.open,
    xhrSend: XMLHttpRequest.prototype.send,
    toString: Function.prototype.toString
  };

  addEventListener('pointerdown', () => events.pointer++, {passive:true});
  addEventListener('keydown', () => events.key++, {passive:true});
  addEventListener('focus', () => events.focus++, {passive:true});
  document.addEventListener('visibilitychange', () => { if (document.hidden) events.hidden++; }, {passive:true});

  try {
    new MutationObserver(list => {
      for (const m of list) {
        for (const node of m.addedNodes || []) {
          if (node && node.nodeType === 1 && String(node.tagName).toLowerCase() === 'script') events.scriptAdded++;
        }
      }
    }).observe(document.documentElement, {subtree:true, childList:true});
  } catch {}

  function nativeFn(fn) {
    try { return /\\[native code\\]/.test(native.toString.call(fn)); } catch { return false; }
  }

  function automationGlobals() {
    return !!(
      navigator.webdriver ||
      window.__playwright__ || window.__pw_manual__ || window.__playwright_evaluation_script__ ||
      window.__puppeteer_evaluation_script__ || window.__PUPPETEER_SCRIPT__ ||
      window._phantom || window.callPhantom || window.__nightmare__ ||
      window.domAutomation || window.domAutomationController ||
      window.GM || window.GM_info || window.GM_xmlhttpRequest ||
      window.unsafeWindow
    );
  }

  function altered() {
    return (
      !nativeFn(history.pushState) ||
      !nativeFn(history.replaceState) ||
      !nativeFn(Node.prototype.appendChild) ||
      !nativeFn(Document.prototype.querySelector) ||
      !nativeFn(Document.prototype.querySelectorAll) ||
      !nativeFn(Document.prototype.getElementById) ||
      !nativeFn(window.fetch) ||
      !nativeFn(XMLHttpRequest.prototype.open) ||
      !nativeFn(XMLHttpRequest.prototype.send)
    );
  }

  function collect() {
    const marker = document.querySelector('meta[name="ab-challenge"]');
    const domTampered = !document.documentElement || !document.body || !marker;
    const timingAnomaly = (performance.now() - started < 80);
    return {
      webdriver: !!navigator.webdriver,
      webdriverGlobal: automationGlobals(),
      playwright: !!window.__playwright__ || !!window.__pw_manual__ || !!window.__playwright_evaluation_script__,
      puppeteer: !!window.__puppeteer_evaluation_script__ || !!window.__PUPPETEER_SCRIPT__,
      domTampered,
      nativeApiTampered: altered(),
      nativeReferenceChanged:
        native.pushState !== history.pushState ||
        native.replaceState !== history.replaceState ||
        native.appendChild !== Node.prototype.appendChild ||
        native.querySelector !== Document.prototype.querySelector ||
        native.querySelectorAll !== Document.prototype.querySelectorAll ||
        native.getElementById !== Document.prototype.getElementById ||
        native.fetch !== window.fetch ||
        native.xhrOpen !== XMLHttpRequest.prototype.open ||
        native.xhrSend !== XMLHttpRequest.prototype.send,
      visibilityHiddenTooOften: events.hidden >= 4,
      scriptInjection: events.scriptAdded > 0,
      timingAnomaly,
      events: [events.pointer, events.key, events.focus, events.hidden, events.scriptAdded],
      ua: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
  }

  async function send(body) {
    try {
      const r = await fetch('/v1/client/telemetry', {
        method:'POST',
        credentials:'same-origin',
        headers:{'content-type':'application/json'},
        body:JSON.stringify(body),
        keepalive:true,
        cache:'no-store'
      });
      return r.ok;
    } catch { return false; }
  }

  (async () => {
    await send(collect());
    const timer = setInterval(() => send(collect()), 2000);
    setTimeout(() => clearInterval(timer), 15000);
  })();
})();`;
