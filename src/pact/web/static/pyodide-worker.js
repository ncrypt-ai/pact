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
    const response = await fetch("/app/pact-browser-core.pyz");
    pyodide.unpackArchive(await response.arrayBuffer(), "zip");
    await pyodide.runPythonAsync("import pact.browser");
    return pyodide;
  })();
  return pyodideReady;
}

async function loadFeature(pyodide, feature) {
  const response = await fetch(`/app/pact-browser-${feature}.pyz`);
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
