const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const DEFAULT_LENGTH = 32;
const DEFAULT_COUNT = 1;
const MAX_LENGTH = 4096;
const MAX_COUNT = 200;

const SIMILAR = new Set("Il1O0B8G6S5Z2".split(""));
const AMBIGUOUS_SYMBOLS = new Set("{}[]()/\\'\"`~,;:.<>".split(""));

const elements = {
  lengthInput: document.querySelector("#length-input"),
  lengthValue: document.querySelector("#length-value"),
  countInput: document.querySelector("#count-input"),
  presetSelect: document.querySelector("#strength-select"),
  customCharset: document.querySelector("#custom-charset"),
  uppercaseToggle: document.querySelector("#uppercase-toggle"),
  lowercaseToggle: document.querySelector("#lowercase-toggle"),
  numbersToggle: document.querySelector("#numbers-toggle"),
  symbolsToggle: document.querySelector("#symbols-toggle"),
  excludeSimilarToggle: document.querySelector("#exclude-similar-toggle"),
  weightedOnlyToggle: document.querySelector("#weighted-only-toggle"),
  entropyToggle: document.querySelector("#entropy-toggle"),
  generateButton: document.querySelector("#generate-button"),
  copyButton: document.querySelector("#copy-button"),
  downloadButton: document.querySelector("#download-button"),
  clearButton: document.querySelector("#clear-button"),
  status: document.querySelector("#status"),
  policySummary: document.querySelector("#policy-summary"),
  metricPoolSize: document.querySelector("#metric-pool-size"),
  metricRequired: document.querySelector("#metric-required"),
  metricCount: document.querySelector("#metric-count"),
  metricEntropy: document.querySelector("#metric-entropy"),
  metricStrength: document.querySelector("#metric-strength"),
  metricMode: document.querySelector("#metric-mode"),
  policyBanner: document.querySelector("#policy-banner"),
  poolModeBadge: document.querySelector("#pool-mode-badge"),
  poolDescription: document.querySelector("#pool-description"),
  poolPreview: document.querySelector("#pool-preview"),
  coverageBadge: document.querySelector("#coverage-badge"),
  rulesDescription: document.querySelector("#rules-description"),
  rulesPreview: document.querySelector("#rules-preview"),
  outputBanner: document.querySelector("#output-banner"),
  outputStatus: document.querySelector("#output-status"),
  outputNote: document.querySelector("#output-note"),
  output: document.querySelector("#output"),
  typeButtons: [...document.querySelectorAll(".type-pill")],
  numbersCard: document.querySelector("#numbers-card"),
  symbolsCard: document.querySelector("#symbols-card"),
  uppercaseCard: document.querySelector("#uppercase-card"),
  lowercaseCard: document.querySelector("#lowercase-card"),
};

let currentPasswords = [];

function cryptoAvailable() {
  return typeof globalThis.crypto?.getRandomValues === "function";
}

function setStatus(message, kind = "") {
  elements.status.textContent = message;
  elements.status.className = `status${kind ? ` ${kind}` : ""}`;
}

function setOutputStatus(message, kind = "") {
  elements.outputStatus.textContent = message;
  elements.outputStatus.className = `status${kind ? ` ${kind}` : ""}`;
}

function setToggleAvailability(element, enabled) {
  element.disabled = !enabled;
  const card = element.closest(".toggle-card");
  if (card) {
    card.classList.toggle("disabled", !enabled);
  }
}

function uniqueChars(chars) {
  return [...new Set(chars.split(""))];
}

function filterCharset(chars, excludeSimilar, preserveDuplicates = false) {
  const filtered = [];
  const seen = new Set();

  for (const char of chars) {
    if (excludeSimilar && (SIMILAR.has(char) || AMBIGUOUS_SYMBOLS.has(char))) {
      continue;
    }

    if (!preserveDuplicates && seen.has(char)) {
      continue;
    }

    filtered.push(char);
    seen.add(char);
  }

  return filtered;
}

function classFlagsProvided() {
  return (
    elements.uppercaseToggle.checked ||
    elements.lowercaseToggle.checked ||
    elements.numbersToggle.checked ||
    elements.symbolsToggle.checked
  );
}

function buildPools(config) {
  if (config.customCharset) {
    const custom = filterCharset(
      config.customCharset,
      config.excludeSimilar,
      config.weightedOnly
    );

    if (!custom.length) {
      throw new Error("The custom character set is empty after filtering.");
    }

    return {
      mode: "custom",
      pools: [custom],
      allChars: custom,
      activeLabels: ["Custom charset"],
    };
  }

  const anyFlags = classFlagsProvided();
  const useUpper = config.uppercase || !anyFlags;
  const useLower = config.lowercase || !anyFlags;
  const useNumbers = config.numbers || !anyFlags;
  const useSymbols = config.symbols || !anyFlags;

  const descriptors = [
    ["Uppercase", useUpper, UPPER],
    ["Lowercase", useLower, LOWER],
    ["Numbers", useNumbers, DIGITS],
    ["Symbols", useSymbols, SYMBOLS],
  ];

  const pools = [];
  const activeLabels = [];

  for (const [label, active, chars] of descriptors) {
    if (!active) {
      continue;
    }

    const pool = filterCharset(chars, config.excludeSimilar, false);
    if (pool.length) {
      pools.push(pool);
      activeLabels.push(label);
    }
  }

  if (!pools.length) {
    throw new Error("No characters available after filtering. Adjust the active rules.");
  }

  return {
    mode: "classes",
    pools,
    allChars: pools.flat(),
    activeLabels,
  };
}

function randomUint32() {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return values[0];
}

function randomIndex(size) {
  if (size <= 0) {
    throw new Error("Random selection requested from an empty pool.");
  }

  const max = 0x100000000;
  const limit = Math.floor(max / size) * size;
  let value = randomUint32();

  while (value >= limit) {
    value = randomUint32();
  }

  return value % size;
}

function chooseOne(pool) {
  return pool[randomIndex(pool.length)];
}

function shuffle(items) {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [copy[index], copy[swapIndex]] = [copy[swapIndex], copy[index]];
  }
  return copy;
}

function generatePassword(length, pools) {
  if (length < pools.length) {
    throw new Error(`Length ${length} is too short for ${pools.length} required character groups.`);
  }

  const required = pools.map((pool) => chooseOne(pool));
  const allChars = pools.flat();
  const remainder = Array.from({ length: length - required.length }, () => chooseOne(allChars));
  return shuffle(required.concat(remainder)).join("");
}

function estimateEntropyBits(length, allChars) {
  if (length <= 0 || !allChars.length) {
    return 0;
  }

  const counts = new Map();
  for (const char of allChars) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }

  const total = allChars.length;
  let bitsPerChar = 0;
  for (const count of counts.values()) {
    const probability = count / total;
    bitsPerChar -= probability * Math.log2(probability);
  }

  return length * bitsPerChar;
}

function entropyLabel(bits) {
  if (bits < 50) {
    return "weak";
  }
  if (bits < 80) {
    return "fair";
  }
  if (bits < 120) {
    return "strong";
  }
  return "very strong";
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function applyPreset(preset) {
  elements.presetSelect.value = preset;

  if (preset === "default") {
    elements.lengthInput.value = "32";
    elements.countInput.value = "1";
    elements.customCharset.value = "";
    elements.uppercaseToggle.checked = true;
    elements.lowercaseToggle.checked = true;
    elements.numbersToggle.checked = true;
    elements.symbolsToggle.checked = true;
    elements.excludeSimilarToggle.checked = false;
    elements.weightedOnlyToggle.checked = false;
    syncQuickMode("default");
    return;
  }

  if (preset === "secure") {
    elements.lengthInput.value = "32";
    elements.countInput.value = "1";
    elements.customCharset.value = "";
    elements.uppercaseToggle.checked = true;
    elements.lowercaseToggle.checked = true;
    elements.numbersToggle.checked = true;
    elements.symbolsToggle.checked = true;
    elements.excludeSimilarToggle.checked = true;
    elements.weightedOnlyToggle.checked = false;
    syncQuickMode("default");
    return;
  }

  if (preset === "memorable") {
    elements.lengthInput.value = "20";
    elements.countInput.value = "1";
    elements.customCharset.value = "";
    elements.uppercaseToggle.checked = true;
    elements.lowercaseToggle.checked = true;
    elements.numbersToggle.checked = true;
    elements.symbolsToggle.checked = false;
    elements.excludeSimilarToggle.checked = true;
    elements.weightedOnlyToggle.checked = false;
    syncQuickMode("memorable");
    return;
  }

  if (preset === "pin") {
    elements.lengthInput.value = "8";
    elements.countInput.value = "1";
    elements.customCharset.value = "";
    elements.uppercaseToggle.checked = false;
    elements.lowercaseToggle.checked = false;
    elements.numbersToggle.checked = true;
    elements.symbolsToggle.checked = false;
    elements.excludeSimilarToggle.checked = false;
    elements.weightedOnlyToggle.checked = false;
    syncQuickMode("pin");
    return;
  }

  if (preset === "hex") {
    elements.lengthInput.value = "40";
    elements.countInput.value = "1";
    elements.customCharset.value = "0123456789abcdef";
    elements.uppercaseToggle.checked = false;
    elements.lowercaseToggle.checked = false;
    elements.numbersToggle.checked = false;
    elements.symbolsToggle.checked = false;
    elements.excludeSimilarToggle.checked = false;
    elements.weightedOnlyToggle.checked = false;
    syncQuickMode("hex");
  }
}

function syncQuickMode(preset) {
  const quickType = preset === "secure" ? "default" : preset;
  elements.lengthValue.textContent = elements.lengthInput.value;

  for (const button of elements.typeButtons) {
    const active = button.dataset.type === quickType;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }

  const randomLike = quickType === "default";
  const memorable = quickType === "memorable";
  const pin = quickType === "pin";
  const hex = quickType === "hex";

  setToggleAvailability(elements.uppercaseToggle, !pin && !hex);
  setToggleAvailability(elements.lowercaseToggle, !pin && !hex);
  setToggleAvailability(elements.numbersToggle, !hex);
  setToggleAvailability(elements.symbolsToggle, randomLike);

  elements.numbersCard.classList.toggle("highlighted", randomLike || memorable || pin);
  elements.symbolsCard.classList.toggle("highlighted", randomLike);
  elements.uppercaseCard.classList.toggle("highlighted", randomLike || memorable);
  elements.lowercaseCard.classList.toggle("highlighted", randomLike || memorable || hex);
}

function getConfig() {
  const length = clamp(
    parsePositiveInteger(elements.lengthInput.value, DEFAULT_LENGTH),
    1,
    MAX_LENGTH
  );
  const count = clamp(
    parsePositiveInteger(elements.countInput.value, DEFAULT_COUNT),
    1,
    MAX_COUNT
  );

  elements.lengthInput.value = String(length);
  elements.countInput.value = String(count);

  return {
    length,
    count,
    uppercase: elements.uppercaseToggle.checked,
    lowercase: elements.lowercaseToggle.checked,
    numbers: elements.numbersToggle.checked,
    symbols: elements.symbolsToggle.checked,
    excludeSimilar: elements.excludeSimilarToggle.checked,
    customCharset: elements.customCharset.value,
    weightedOnly: elements.weightedOnlyToggle.checked,
    showEntropy: elements.entropyToggle.checked,
  };
}

function updatePolicyPreview() {
  try {
    const config = getConfig();
    const detail = buildPools(config);
    const uniquePool = uniqueChars(detail.allChars.join(""));
    const entropyBits = estimateEntropyBits(config.length, detail.allChars);
    const summaryLabels = detail.activeLabels.join(", ").toLowerCase();
    const coverageActive = detail.mode === "classes";
    const displayMode = elements.presetSelect.value === "default" ? "random" : elements.presetSelect.value;

    elements.metricPoolSize.textContent = String(uniquePool.length);
    elements.metricRequired.textContent = String(detail.pools.length);
    elements.metricCount.textContent = String(currentPasswords.length);
    elements.metricEntropy.textContent = config.showEntropy ? entropyBits.toFixed(2) : "off";
    elements.metricStrength.textContent = config.showEntropy ? entropyLabel(entropyBits) : "hidden";
    elements.metricMode.textContent = displayMode;
    elements.poolModeBadge.textContent = detail.mode === "custom" ? "Custom set" : "Class-based";
    elements.poolDescription.textContent =
      detail.mode === "custom"
        ? "Using the custom character set exactly as configured."
        : `Using ${summaryLabels}.`;
    elements.poolPreview.textContent = detail.allChars.join("");
    elements.coverageBadge.textContent = coverageActive ? "Coverage on" : "Coverage off";
    elements.rulesDescription.textContent = coverageActive
      ? "At least one character from each active class is guaranteed."
      : "Custom character mode draws from one supplied pool, so class coverage is not applied.";
    elements.rulesPreview.textContent = coverageActive
      ? `${detail.activeLabels.join(", ")} will each appear at least once.`
      : "Characters are drawn from your custom set with optional duplicate weighting.";
    elements.policySummary.textContent = `${config.length} characters, ${config.count} password${config.count === 1 ? "" : "s"}, ${detail.mode === "custom" ? "custom charset" : displayMode}, generated locally.`;
    elements.policyBanner.textContent = coverageActive
      ? "Class coverage is active, so each enabled class is represented in every generated password."
      : "Custom mode is active, which gives full control over the character pool.";
    elements.policyBanner.className = `risk-banner ${coverageActive ? "safe" : ""}`.trim();
    elements.lengthValue.textContent = String(config.length);
  } catch (error) {
    elements.metricPoolSize.textContent = "0";
    elements.metricRequired.textContent = "0";
    elements.metricEntropy.textContent = "0";
    elements.metricStrength.textContent = "n/a";
    elements.metricMode.textContent = "invalid";
    elements.poolModeBadge.textContent = "Needs input";
    elements.poolDescription.textContent = error.message;
    elements.poolPreview.textContent = "";
    elements.coverageBadge.textContent = "Blocked";
    elements.rulesDescription.textContent = "Adjust the policy to restore a valid character pool.";
    elements.rulesPreview.textContent = "No valid generation rules available yet.";
    elements.policySummary.textContent = error.message;
    elements.policyBanner.textContent = error.message;
    elements.policyBanner.className = "risk-banner warn";
    elements.lengthValue.textContent = elements.lengthInput.value;
  }
}

function renderOutput(passwords, detail, config) {
  const outputText = passwords.join("\n");
  elements.output.textContent = outputText;
  elements.copyButton.disabled = passwords.length === 0;
  elements.downloadButton.disabled = passwords.length === 0;
  elements.metricCount.textContent = String(passwords.length);
  elements.outputBanner.textContent =
    passwords.length === 1
      ? "One password generated and ready to copy."
      : `${passwords.length} passwords generated and ready to copy or download.`;
  elements.outputBanner.className = "risk-banner safe";

  if (config.showEntropy) {
    const bits = estimateEntropyBits(config.length, detail.allChars);
    const label = entropyLabel(bits);
    elements.outputNote.textContent = `Approximate entropy: ${bits.toFixed(2)} bits (${label}). Clipboard copy works best in secure browser contexts such as GitHub Pages or localhost.`;
  } else {
    elements.outputNote.textContent = "Clipboard copy works best in secure browser contexts such as GitHub Pages or localhost.";
  }

  if (passwords.length > 1) {
    elements.outputBanner.textContent = `${passwords.length} passwords generated. The first is shown first and the full batch is ready to copy or download.`;
  }
}

function generatePasswords() {
  try {
    if (!cryptoAvailable()) {
      throw new Error("Web Crypto is unavailable in this browser, so secure generation cannot run.");
    }

    const config = getConfig();

    if (config.weightedOnly && !config.customCharset) {
      throw new Error("Weighted custom mode requires a custom character set.");
    }

    const detail = buildPools(config);
    currentPasswords = Array.from({ length: config.count }, () =>
      generatePassword(config.length, detail.pools)
    );

    renderOutput(currentPasswords, detail, config);
    setStatus(`Generated ${config.count} password${config.count === 1 ? "" : "s"} locally.`, "success");
    setOutputStatus("Generation complete.", "success");
    updatePolicyPreview();
  } catch (error) {
    currentPasswords = [];
    elements.output.textContent = "No output yet.";
    elements.copyButton.disabled = true;
    elements.downloadButton.disabled = true;
    elements.outputBanner.textContent = error.message;
    elements.outputBanner.className = "risk-banner warn";
    setStatus(error.message, "error");
    setOutputStatus("Generation failed.", "error");
    updatePolicyPreview();
  }
}

async function copyOutput() {
  if (!currentPasswords.length) {
    return;
  }

  if (!window.isSecureContext || !navigator.clipboard?.writeText) {
    setOutputStatus("Clipboard copy requires a secure browser context. You can still copy from the output panel.", "warn");
    return;
  }

  const outputText = currentPasswords.join("\n");

  try {
    await navigator.clipboard.writeText(outputText);
    setOutputStatus("Copied output to the clipboard.", "success");
  } catch (error) {
    setOutputStatus("Clipboard copy was blocked by the browser. You can still copy from the output panel.", "warn");
  }
}

function downloadOutput() {
  if (!currentPasswords.length) {
    return;
  }

  const blob = new Blob([currentPasswords.join("\n")], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "passwords.txt";
  link.click();
  URL.revokeObjectURL(url);
  setOutputStatus("Downloaded passwords.txt.", "success");
}

function clearOutput() {
  currentPasswords = [];
  elements.output.textContent = "No output yet.";
  elements.copyButton.disabled = true;
  elements.downloadButton.disabled = true;
  elements.outputBanner.textContent = "Generate passwords to populate this panel.";
  elements.outputBanner.className = "risk-banner";
  setStatus("Output cleared.", "success");
  setOutputStatus("", "");
  updatePolicyPreview();
}

function clearSensitiveState() {
  currentPasswords = [];
  elements.output.textContent = "Output cleared.";
}

elements.generateButton.addEventListener("click", generatePasswords);
elements.copyButton.addEventListener("click", copyOutput);
elements.downloadButton.addEventListener("click", downloadOutput);
elements.clearButton.addEventListener("click", clearOutput);
elements.presetSelect.addEventListener("change", (event) => {
  applyPreset(event.target.value);
  updatePolicyPreview();
  setStatus(`Preset changed to ${event.target.selectedOptions[0].textContent}.`, "success");
});

for (const button of elements.typeButtons) {
  button.addEventListener("click", () => {
    applyPreset(button.dataset.type);
    updatePolicyPreview();
    generatePasswords();
  });
}

for (const field of [
  elements.lengthInput,
  elements.countInput,
  elements.customCharset,
  elements.uppercaseToggle,
  elements.lowercaseToggle,
  elements.numbersToggle,
  elements.symbolsToggle,
  elements.excludeSimilarToggle,
  elements.weightedOnlyToggle,
  elements.entropyToggle,
]) {
  field.addEventListener("input", updatePolicyPreview);
  field.addEventListener("change", updatePolicyPreview);
}

elements.lengthInput.addEventListener("input", () => {
  elements.lengthValue.textContent = elements.lengthInput.value;
});

window.addEventListener("pagehide", clearSensitiveState);

applyPreset("default");
updatePolicyPreview();

if (!cryptoAvailable()) {
  setStatus("This browser does not expose Web Crypto, so secure generation is unavailable.", "error");
  elements.generateButton.disabled = true;
  elements.copyButton.disabled = true;
  elements.downloadButton.disabled = true;
}
