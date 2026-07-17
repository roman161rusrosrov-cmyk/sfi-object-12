(() => {
  "use strict";

  const ENTRY_PATH = "assets/secure/entry.json";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const assetUrls = new Map();
  let archive = null;
  let archiveKey = null;
  let failedAttempts = 0;

  const bytesEqual = (bytes, text) =>
    text.length === bytes.length &&
    [...text].every((character, index) => bytes[index] === character.charCodeAt(0));

  const concat = (chunks) => {
    const result = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  };

  const fetchBytes = async (relativePath) => {
    const response = await fetch(new URL(relativePath, document.baseURI), {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) throw new Error("ARCHIVE_UNAVAILABLE");
    return new Uint8Array(await response.arrayBuffer());
  };

  const fetchParts = async (paths) => concat(await Promise.all(paths.map(fetchBytes)));

  const deriveKey = async (password, salt, iterations) => {
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  };

  const decryptEntry = async (password) => {
    if (!globalThis.crypto?.subtle) throw new Error("WEB_CRYPTO_REQUIRED");
    const entryResponse = await fetch(new URL(ENTRY_PATH, document.baseURI), {
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!entryResponse.ok) throw new Error("ARCHIVE_UNAVAILABLE");
    const entry = await entryResponse.json();
    const bytes = await fetchParts(entry.parts);

    if (!bytesEqual(bytes.subarray(0, 4), "SFM2")) throw new Error("ARCHIVE_INVALID");
    const iterations = new DataView(bytes.buffer, bytes.byteOffset + 4, 4).getUint32(0);
    const salt = bytes.slice(8, 24);
    const iv = bytes.slice(24, 36);
    const ciphertext = bytes.slice(36);
    const key = await deriveKey(password, salt, iterations);
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    const parsed = JSON.parse(decoder.decode(clear));
    if (parsed.version !== 2 || !parsed.pages || !parsed.assets) throw new Error("ARCHIVE_INVALID");
    return { key, parsed };
  };

  const decryptAsset = async (descriptor) => {
    const bytes = await fetchParts(descriptor.parts);
    if (!bytesEqual(bytes.subarray(0, 4), "SFA2")) throw new Error("ASSET_INVALID");
    const iv = bytes.slice(4, 16);
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      archiveKey,
      bytes.slice(16)
    );
    return URL.createObjectURL(new Blob([clear], { type: descriptor.mime }));
  };

  const pageName = () => {
    const name = location.pathname.split("/").filter(Boolean).at(-1) || "index.html";
    return name.endsWith(".html") ? name : "index.html";
  };

  const addRelockButton = () => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sfi-relock";
    button.textContent = "Закрыть архив";
    button.addEventListener("click", () => {
      archive = null;
      archiveKey = null;
      for (const url of assetUrls.values()) URL.revokeObjectURL(url);
      assetUrls.clear();
      location.reload();
    });
    document.body.append(button);
  };

  const renderPage = async (name, push = false) => {
    const page = archive.pages[name] || archive.pages["index.html"];
    let html = page.body;

    await Promise.all(
      Object.entries(archive.assets).map(async ([reference, descriptor]) => {
        if (!html.includes(reference)) return;
        let url = assetUrls.get(reference);
        if (!url) {
          url = await decryptAsset(descriptor);
          assetUrls.set(reference, url);
        }
        html = html.split(reference).join(url);
      })
    );

    document.body.innerHTML = html;
    document.title = page.title;
    const description = document.querySelector('meta[name="description"]');
    if (description) description.content = page.description;
    document.documentElement.classList.remove("sfi-locked");
    addRelockButton();

    if (push) history.pushState({ page: name }, "", name);
    scrollTo({ top: 0, behavior: "instant" });
  };

  const createGate = () => {
    const gate = document.createElement("section");
    gate.id = "sfi-access-gate";
    gate.setAttribute("role", "dialog");
    gate.setAttribute("aria-modal", "true");
    gate.setAttribute("aria-labelledby", "sfi-gate-title");
    gate.innerHTML = `
      <div class="sfi-gate-card">
        <p class="sfi-gate-kicker">SFI // Encrypted archive</p>
        <h1 class="sfi-gate-title" id="sfi-gate-title">Доступ ограничен</h1>
        <p class="sfi-gate-copy">Материалы зашифрованы. Введите персональный код допуска для локальной расшифровки архива.</p>
        <form class="sfi-gate-form" novalidate>
          <label class="sfi-gate-label" for="sfi-gate-password">Код доступа</label>
          <div class="sfi-gate-input-wrap">
            <input class="sfi-gate-input" id="sfi-gate-password" name="password" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" required aria-describedby="sfi-gate-error">
            <button class="sfi-gate-peek" type="button" aria-label="Показать пароль" title="Показать пароль">◉</button>
          </div>
          <button class="sfi-gate-submit" type="submit">Расшифровать архив</button>
          <p class="sfi-gate-error" id="sfi-gate-error" role="alert" aria-live="polite"></p>
        </form>
        <div class="sfi-gate-status">AES-256-GCM // local decryption</div>
      </div>`;
    document.body.append(gate);

    const form = gate.querySelector(".sfi-gate-form");
    const input = gate.querySelector(".sfi-gate-input");
    const submit = gate.querySelector(".sfi-gate-submit");
    const error = gate.querySelector(".sfi-gate-error");
    const peek = gate.querySelector(".sfi-gate-peek");

    peek.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      peek.setAttribute("aria-label", show ? "Скрыть пароль" : "Показать пароль");
      peek.setAttribute("title", show ? "Скрыть пароль" : "Показать пароль");
      input.focus();
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      error.textContent = "";
      if (!input.value) {
        error.textContent = "ВВЕДИТЕ КОД ДОСТУПА";
        input.focus();
        return;
      }

      submit.disabled = true;
      submit.textContent = "РАСШИФРОВКА...";
      const password = input.value;
      input.value = "";

      try {
        const unlocked = await decryptEntry(password);
        archiveKey = unlocked.key;
        archive = unlocked.parsed;
        await renderPage(pageName());
      } catch (reason) {
        failedAttempts += 1;
        const unavailable = reason?.message === "ARCHIVE_UNAVAILABLE";
        error.textContent = unavailable
          ? "АРХИВ ВРЕМЕННО НЕДОСТУПЕН"
          : "КОД ДОСТУПА НЕ ПРИНЯТ";
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(800 + failedAttempts * 450, 3500))
        );
        submit.disabled = false;
        submit.textContent = "РАСШИФРОВАТЬ АРХИВ";
        input.focus();
      }
    });

    input.focus();
  };

  document.addEventListener("click", (event) => {
    if (!archive) return;
    const link = event.target.closest("a[href]");
    if (!link || link.target || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href, location.href);
    const name = url.pathname.split("/").filter(Boolean).at(-1);
    if (url.origin !== location.origin || !archive.pages[name]) return;
    event.preventDefault();
    renderPage(name, true).catch(() => location.assign(url.href));
  });

  addEventListener("popstate", () => {
    if (archive) renderPage(pageName()).catch(() => location.reload());
  });

  const initialize = () => {
    document.querySelector("#sfi-secure-root")?.remove();
    createGate();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
