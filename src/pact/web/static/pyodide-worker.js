let pyodideReady = null;
const loadedFeaturePacks = new Set();
const installedPackageSets = new Set();

const PYODIDE_BASE_URL = "https://cdn.jsdelivr.net/pyodide/v0.28.3/full/";
const PYODIDE_URL = `${PYODIDE_BASE_URL}pyodide.js`;
const PYODIDE_SHA384 =
  "sha384-4X7gSPzQ4pHfjTE5aBEPJAQcHu55sciq+NWO3OUOZ3zHSJhn4te9CBjUyRSr+nei";
const PACKAGE_SETS = {
  core: [
    "https://files.pythonhosted.org/packages/4d/78/119878110660b2ad709888c8a1614fce7e2fab39080ab960656dc8605bf6/rfc8785-0.1.4-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/00/62/03f171160749e7c3b433267ab00b8cf33972e42a9500acf4ba1ffe4e7518/fe25519-1.5.0-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/d8/f8/b368dc00952c6b035cb6969db34bae1b574be2be3d16090c861b56116002/ge25519-1.5.1-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/ff/9d/75d171197827ff3b4cc85d6f6487a09fc941b0ad55ee9fcdc987777419dd/parts-1.7.0-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/8a/30/2359492441dafdbf87119c43066e1e96145c59496cfc1a13560dfacfa2d6/oblivious-7.0.0-py3-none-any.whl"
  ],
  documents: [
    "https://files.pythonhosted.org/packages/07/6c/aa3f2f849e01cb6a001cd8554a88d4c77c5c1a31c95bdf1cf9301e6d9ef4/defusedxml-0.7.1-py2.py3-none-any.whl",
    "https://files.pythonhosted.org/packages/49/e6/136aa8993a2ae7214e0b0ef2edaa0d2e08d1d4e4982635b08a835ff31ec8/pypdf-6.14.2-py3-none-any.whl"
  ]
};

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
    const pyodide = await loadPyodide({ indexURL: PYODIDE_BASE_URL });
    await pyodide.loadPackage(["micropip", "cryptography"]);
    await installPackageSet(pyodide, "core");
    const response = await fetch(`/pact/web/pact-browser-core.pyz?v=${Date.now()}`, {
      cache: "no-store"
    });
    pyodide.unpackArchive(await response.arrayBuffer(), "zip");
    await pyodide.runPythonAsync("import pact.browser");
    return pyodide;
  })();
  return pyodideReady;
}

async function installPackageSet(pyodide, name) {
  if (installedPackageSets.has(name)) {
    return;
  }
  const packages = PACKAGE_SETS[name] || [];
  if (!packages.length) {
    installedPackageSets.add(name);
    return;
  }
  await pyodide.runPythonAsync(`
import micropip
await micropip.install(${JSON.stringify(packages)}, deps=False)
`);
  installedPackageSets.add(name);
}

async function loadFeature(pyodide, feature) {
  if (feature === "documents") {
    await installPackageSet(pyodide, "documents");
  }
  if (loadedFeaturePacks.has(feature)) {
    return;
  }
  const response = await fetch(`/pact/web/pact-browser-${feature}.pyz?v=${Date.now()}`, {
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error(`feature pack unavailable: ${feature}`);
  }
  pyodide.unpackArchive(await response.arrayBuffer(), "zip");
  loadedFeaturePacks.add(feature);
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
