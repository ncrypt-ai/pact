let pyodideReady = null;

async function loadRuntime() {
  if (pyodideReady) {
    return pyodideReady;
  }
  pyodideReady = (async () => {
    importScripts("https://cdn.jsdelivr.net/pyodide/v0.28.3/full/pyodide.js");
    const pyodide = await loadPyodide();
    await pyodide.loadPackage(["micropip", "cryptography"]);
    const micropip = pyodide.pyimport("micropip");
    await micropip.install(["rfc8785", "defusedxml", "pypdf"]);
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
