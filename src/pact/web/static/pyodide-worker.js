let pyodideReady = null;

const PYODIDE_URL = "https://cdn.jsdelivr.net/pyodide/v0.28.3/full/pyodide.js";
const PYODIDE_SHA384 =
  "sha384-4X7gSPzQ4pHfjTE5aBEPJAQcHu55sciq+NWO3OUOZ3zHSJhn4te9CBjUyRSr+nei";

function base64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function importPinnedScript(url, expectedIntegrity) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`failed to load ${url}`);
  }
  const script = await response.text();
  const digest = await crypto.subtle.digest(
    "SHA-384",
    new TextEncoder().encode(script)
  );
  const actualIntegrity = `sha384-${base64(new Uint8Array(digest))}`;
  if (actualIntegrity !== expectedIntegrity) {
    throw new Error(`integrity check failed for ${url}`);
  }
  const objectUrl = URL.createObjectURL(
    new Blob([script], { type: "text/javascript" })
  );
  try {
    importScripts(objectUrl);
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

async function loadRuntime() {
  if (pyodideReady) {
    return pyodideReady;
  }
  pyodideReady = (async () => {
    await importPinnedScript(PYODIDE_URL, PYODIDE_SHA384);
    const pyodide = await loadPyodide();
    await pyodide.loadPackage(["micropip", "cryptography"]);
    const micropip = pyodide.pyimport("micropip");
    await micropip.install(["rfc8785", "defusedxml", "pypdf", "oblivious"]);
    const response = await fetch(`/pact/pact-browser-core.pyz?v=${Date.now()}`, {
      cache: "no-store"
    });
    pyodide.unpackArchive(await response.arrayBuffer(), "zip");
    await pyodide.runPythonAsync("import pact.browser");
    return pyodide;
  })();
  return pyodideReady;
}

async function loadFeature(pyodide, feature) {
  const response = await fetch(`/pact/pact-browser-${feature}.pyz?v=${Date.now()}`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error(`feature pack unavailable: ${feature}`);
  }
  pyodide.unpackArchive(await response.arrayBuffer(), "zip");
}

self.onmessage = async (event) => {
  const { id, name, args = [], feature } = event.data;
  try {
    const pyodide = await loadRuntime();
    if (feature) {
      await loadFeature(pyodide, feature);
    }
    await pyodide.runPythonAsync("import importlib, pact.browser; importlib.reload(pact.browser)");
    const module = pyodide.pyimport("pact.browser");
    const result = module[name](...args);
    self.postMessage({ id, ok: true, result });
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: error && error.message ? error.message : String(error)
    });
  }
};
