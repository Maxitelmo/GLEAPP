"use strict";
/* The interface in the examiner's language (gleapp/i18n.py says what is and is not
   translated).

   The page and app.js are written in English and stay that way: this file translates
   what they put on screen. The catalog (window.GLEAPP_I18N, from /i18n.js) maps an
   English string, as the page shows it, to its translation; a key holding {name}
   placeholders matches any text of that shape, so "Retry {n} failed files" covers
   every count. Whitespace runs count as one space and the ends are ignored, so a
   string written over several lines of a template matches its one-line key. Text the
   catalog does not hold stays in English: a new message is untranslated, never lost.

   Text is translated as it reaches the page (a MutationObserver), text nodes and the
   title, placeholder, aria-label, alt and label attributes, and the browser's own
   alert, confirm and prompt. Nothing inside an element marked translate="no" is
   touched, which is how evidence (names, paths, metadata, the examiner's category and
   flag names, the hex view) stays exactly as stored; it is the HTML attribute browser
   translators honour too. An <option> with no value attribute is given its English text
   as one before its label changes, so what it selects never changes with the language.

   A placeholder named n, m, k, a, b, c, d, h, p, id, code, saved or total stands for a
   number (a count, a date, a percentage): it matches text with no letter in it, so
   "{n} errored" covers "3 errored" and not every sentence that ends in "errored". Any
   other name matches any text.

   A translation may write {name?text if set|text if empty} for a placeholder that holds
   an English plural ending ("s" or nothing), since a Spanish plural is not always one.
   A key's {name:t} asks for what that placeholder stands for to be translated too, for
   a message built from another one the catalog holds. */
(function () {
  const cfg = window.GLEAPP_I18N || {};
  const lang = cfg.lang || "en";
  const messages = cfg.messages || {};
  document.documentElement.lang = lang;

  const norm = s => String(s).replace(/\s+/g, " ").trim();
  const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const KEY_PH = /\{([a-z][a-z0-9_]*)(:t)?\}/g;
  const NUMBERS = new Set(["n", "m", "k", "a", "b", "c", "d", "h", "p", "id", "code", "saved", "total"]);
  const OUT_PH = /\{([a-z][a-z0-9_]*)(\?[^{}]*)?\}/g;

  // exact strings, and the patterns filed by the first (or failing that the last) one
  // or two characters of their fixed text, so a text is tried against a handful of
  // patterns rather than all of them
  const exact = new Map(), patterns = new Map();
  const heads = new Map(), tails = new Map(), loose = [];
  const file = (map, k, p) => { if (!map.has(k)) map.set(k, []); map.get(k).push(p); };
  for (const [key, out] of Object.entries(messages)) {
    const k = norm(key);
    if (!k || typeof out !== "string") continue;
    KEY_PH.lastIndex = 0;
    if (!KEY_PH.test(k)) { exact.set(k, out); continue; }
    patterns.set(k, out);
    const names = [], tr = [];
    let re = "^", last = 0;
    k.replace(KEY_PH, (m, name, t, at) => {
      re += escRe(k.slice(last, at)) + (NUMBERS.has(name) ? "([-+?\\d][^A-Za-z]*?)" : "(.*?)");
      names.push(name); tr.push(!!t); last = at + m.length;
      return m;
    });
    re += escRe(k.slice(last)) + "$";
    // the more fixed text a key has, the more it says: "Any date: {a} – {b}, or none"
    // is tried before "Any date: {a} – {b}", which would also match it
    const p = { re: new RegExp(re, "s"), names, tr, out, lit: k.replace(KEY_PH, "").length };
    const head = k.slice(0, k.indexOf("{")), tail = k.slice(k.lastIndexOf("}") + 1);
    if (head) file(heads, head.slice(0, 2), p);
    else if (tail) file(tails, tail.slice(-2), p);
    else loose.push(p);
  }
  const render = (out, vals) => out.replace(OUT_PH, (m, name, alt) => {
    if (!(name in vals)) return m;
    if (alt == null) return vals[name];
    const [set, empty = ""] = alt.slice(1).split("|");
    return vals[name] ? set : empty;
  });
  const misses = new Set();
  // the translation of one piece of text, or null when the catalog has none
  function tr(text) {
    const n = norm(text);
    if (!n || !/[A-Za-z]/.test(n)) return null;
    const hit = exact.get(n);
    if (hit !== undefined) return hit;
    if (misses.has(n)) return null;
    const cands = [].concat(heads.get(n.slice(0, 2)) || [], heads.get(n.slice(0, 1)) || [],
                            tails.get(n.slice(-2)) || [], tails.get(n.slice(-1)) || [], loose)
      .sort((a, b) => b.lit - a.lit);
    for (const p of cands) {
      const m = p.re.exec(n);
      if (!m) continue;
      const vals = {};
      p.names.forEach((name, i) => {
        const v = m[i + 1];
        vals[name] = p.tr[i] ? (tr(v) ?? v) : v;
      });
      return render(p.out, vals);
    }
    if (misses.size > 20000) misses.clear();
    misses.add(n);
    return null;
  }

  const SKIP = new Set(["SCRIPT", "STYLE", "TEXTAREA", "CODE", "PRE", "KBD", "SAMP"]);
  const ATTRS = ["title", "placeholder", "aria-label", "alt", "label"];
  const held = el => !!(el && el.closest('[translate="no"]'));
  function text(node) {
    const p = node.parentElement;
    if (!p || SKIP.has(p.tagName)) return;
    const v = node.data, t = tr(v);
    if (t == null || t === norm(v)) return;
    if (p.tagName === "OPTION" && !p.hasAttribute("value")) p.setAttribute("value", p.value);
    node.data = v.match(/^\s*/)[0] + t + v.match(/\s*$/)[0];
  }
  function attr(el, name) {
    const v = el.getAttribute(name);
    if (!v) return;
    const t = tr(v);
    if (t != null && t !== v) el.setAttribute(name, t);
  }
  function element(el) {
    for (const a of ATTRS) if (el.hasAttribute(a)) attr(el, a);
  }
  // an element held back is skipped whole; one whose text is code or an input box
  // (SKIP) keeps its tooltip and placeholder translated
  const accept = {
    acceptNode: n => {
      if (n.nodeType !== 1) return NodeFilter.FILTER_ACCEPT;
      if (n.getAttribute("translate") === "no") return NodeFilter.FILTER_REJECT;
      if (SKIP.has(n.tagName)) { element(n); return NodeFilter.FILTER_REJECT; }
      return NodeFilter.FILTER_ACCEPT;
    },
  };
  function apply(root) {
    if (!root || !root.isConnected) return;
    if (root.nodeType === 3) { if (!held(root.parentElement)) text(root); return; }
    if (root.nodeType !== 1 || held(root)) return;
    element(root);
    if (SKIP.has(root.tagName)) return;
    const w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, accept);
    for (let n = w.nextNode(); n; n = w.nextNode()) n.nodeType === 3 ? text(n) : element(n);
  }

  // t("Retry {n} failed files", {n: 3}): for a string app.js places where the observer
  // does not look (inside an element marked translate="no") or builds from parts. The
  // key's own leading and trailing spaces are kept, since a part is joined to others.
  // ``ctx`` tells apart one English word that is two in another language: the catalog's
  // "verb|Copy" is the button, "Copy" the noun the observer sees in a details row.
  function t(key, vals = {}, ctx = "") {
    const k = norm(key);
    const inCtx = ctx ? exact.get(`${ctx}|${k}`) ?? patterns.get(`${ctx}|${k}`) : undefined;
    const out = inCtx ?? exact.get(k) ?? patterns.get(k) ?? k;
    return key.match(/^\s*/)[0] + render(out, vals) + key.match(/\s*$/)[0];
  }

  // a <select> that changes the language: the choice is kept app-wide and shows on reload
  function picker(sel) {
    const langs = cfg.languages || { en: "English" };
    sel.innerHTML = "";
    // "auto" names the language it resolved to, so the choice in effect is on screen
    const auto = new Option(t("System language ({name})", { name: langs[lang] || lang }), "auto");
    auto.setAttribute("translate", "no");   // already in the page's language
    sel.add(auto);
    for (const [code, name] of Object.entries(langs)) {
      const o = new Option(name, code);
      o.setAttribute("translate", "no");    // each language is named in its own
      sel.add(o);
    }
    sel.value = cfg.setting in langs ? cfg.setting : "auto";
    sel.onchange = async () => {
      const r = await fetch("/api/settings", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ language: sel.value }),
      });
      if (r.ok) location.reload();
    };
  }

  window.i18n = { lang, t, tr, apply, picker, help: cfg.help || "/static/help.html",
                  helpStale: !!cfg.help_stale };
  if (lang === "en" || !Object.keys(messages).length) return;

  for (const name of ["alert", "confirm", "prompt"]) {
    const orig = window[name].bind(window);
    window[name] = (msg, ...rest) => orig(msg == null ? msg : (tr(String(msg)) ?? msg), ...rest);
  }
  // loaded from <head>: the observer sees the body as the parser adds it, and one pass
  // when parsing ends picks up anything that arrived before it was watching
  apply(document.documentElement);
  document.addEventListener("DOMContentLoaded", () => apply(document.body));
  new MutationObserver(records => {
    for (const r of records) {
      if (r.type === "childList") r.addedNodes.forEach(apply);
      else if (r.type === "characterData") { if (!held(r.target.parentElement)) text(r.target); }
      else if (!held(r.target)) attr(r.target, r.attributeName);
    }
  }).observe(document.documentElement, {
    childList: true, subtree: true, characterData: true,
    attributes: true, attributeFilter: ATTRS,
  });
})();
