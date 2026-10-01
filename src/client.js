export const CLIENT_SCRIPT = `(() => {
  const start = performance.now();
  const events = { pointer: 0, key: 0, focus: 0, hidden: 0 };
  const native = {
    pushState: history.pushState,
    replaceState: history.replaceState,
    appendChild: Node.prototype.appendChild,
    querySelector: Document.prototype.querySelector,
    getElementById: Document.prototype.getElementById
  };
  addEventListener('pointerdown', () => events.pointer++, {passive:true});
  addEventListener('keydown', () => events.key++, {passive:true});
  addEventListener('focus', () => events.focus++, {passive:true});
  document.addEventListener('visibilitychange', () => { if (document.hidden) events.hidden++; }, {passive:true});

  function fnTampered(fn) {
    try { return !/\\[native code\\]/.test(Function.prototype.toString.call(fn)); } catch { return true; }
  }
  function automationGlobals() {
    return !!(
      navigator.webdriver ||
      window.__playwright__ || window.__pw_manual || window.__playwright_evaluation_script__ ||
      window.__puppeteer_evaluation_script__ || window.__PUPPETEER_SCRIPT__ ||
      window._phantom || window.callPhantom || window.__nightmare__ ||
      window.domAutomation || window.domAutomationController
    );
  }
  function collect() {
    const marker = document.querySelector('meta[name="ab-challenge"]');
    const domTampered = !document.documentElement || !document.body || !marker;
    const nativeApiTampered = fnTampered(history.pushState) || fnTampered(history.replaceState) || fnTampered(Node.prototype.appendChild) || fnTampered(Document.prototype.querySelector) || fnTampered(Document.prototype.getElementById);
    const webdriverGlobal = automationGlobals();
    const timingAnomaly = (performance.now() - start < 80);
    return {
      webdriver: !!navigator.webdriver,
      webdriverGlobal,
      playwright: !!window.__playwright__ || !!window.__pw_manual || !!window.__playwright_evaluation_script__,
      puppeteer: !!window.__puppeteer_evaluation_script__ || !!window.__PUPPETEER_SCRIPT__,
      domTampered,
      nativeApiTampered,
      nativeReferenceChanged: native.pushState !== history.pushState || native.replaceState !== history.replaceState || native.appendChild !== Node.prototype.appendChild || native.querySelector !== Document.prototype.querySelector || native.getElementById !== Document.prototype.getElementById,
      visibilityHiddenTooOften: events.hidden >= 4,
      timingAnomaly,
      events: [events.pointer, events.key, events.focus, events.hidden],
      ua: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
  }
  async function send(path, body) {
    try {
      const r = await fetch(path, { method:'POST', credentials:'same-origin', headers:{'content-type':'application/json'}, body:JSON.stringify(body), keepalive:true, cache:'no-store' });
      return r.ok;
    } catch { return false; }
  }
  (async () => {
    await send('/v1/client/hello', collect());
    const timer = setInterval(() => send('/v1/client/heartbeat', collect()), 2500);
    setTimeout(() => clearInterval(timer), 15000);
  })();
})();`;
