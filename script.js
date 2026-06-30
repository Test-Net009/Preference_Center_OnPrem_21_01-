const {
  preferenceFormId,
  preferenceDetailsApiUrl,
  preferenceHistoryApiUrl,
  submitApiUrl,
  signatureServiceUrl,
  userToken,
  showButtons,
  showLanguageDropdown,
  enableCheckboxes,
  enableRadioButtons,
  enableDropdowns,
  footerAlignment = "left",
  customAttributes,
  receivedType
} = window.consentWidgetConfig;

let createConsentRequestList = [];
let selectedLanguage = "english";
let storedSigning = { bss: null, bssPublicKey: null, sss: null };
let pendingSignController = null;
let currentSnapshot = null;
let consentJwt = null;

const AES_KEY_B64 = "el+1+epeGlCquCYLsk3zyQTsq3KUKQKL9QcV0B9KIS8=";
let globalSSS = null;
let isSSSValid = false;

function uint8ToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(binary);
}
async function encryptPayload(body) {
  const keyBytes = Uint8Array.from(atob(AES_KEY_B64), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(body));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);
  const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.byteLength);
  return uint8ToBase64(combined);
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": userToken || ""
  };
}

// ── IndexedDB helper ──
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("consent-signing-store", 2);
    req.onupgradeneeded = function(e) {
      const db = e.target.result;
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys");
    };
    req.onsuccess = e => resolve({
      put: (store, val, key) => new Promise((res, rej) => {
        const tx = e.target.result.transaction(store, "readwrite");
        const r = tx.objectStore(store).put(val, key);
        r.onsuccess = () => res(); r.onerror = () => rej(r.error);
      }),
      get: (store, key) => new Promise((res, rej) => {
        const tx = e.target.result.transaction(store, "readonly");
        const r = tx.objectStore(store).get(key);
        r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
      }),
    });
    req.onerror = () => reject(req.error);
  });
}

// Generates ECDSA P-256 key pair on first load; private key is non-extractable
// and stored in IndexedDB. Public key is exported as SPKI base64.
async function initSigningKey() {
  try {
    const db = await openDB();
    const existing = await db.get("keys", "signingKeyEC");
    if (existing) return;

    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );

    await db.put("keys", keyPair.privateKey, "signingKeyEC");

    const pubKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const pubKeyB64 = btoa(String.fromCharCode(...new Uint8Array(pubKeyBuffer)));
    await db.put("keys", pubKeyB64, "signingPublicKeyB64");
  } catch (e) {
    console.error("Signing key initialization failed:", e);
  }
}

async function getPublicKeyB64() {
  try {
    const db = await openDB();
    return await db.get("keys", "signingPublicKeyB64");
  } catch (e) {
    return null;
  }
}

// Produces canonical JSON (sorted keys, no whitespace) matching Go's canonicalize.
function canonicalizePayload(obj) {
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalizePayload).join(",") + "]";
  }
  if (obj !== null && typeof obj === "object") {
    var keys = Object.keys(obj).sort();
    return "{" + keys.map(function(k) {
      return JSON.stringify(k) + ":" + canonicalizePayload(obj[k]);
    }).join(",") + "}";
  }
  return JSON.stringify(obj);
}

// Signs using ECDSA-P256; returns base64url IEEE P1363 signature.
async function signPayload(payload) {
  try {
    const db = await openDB();
    const privateKey = await db.get("keys", "signingKeyEC");
    if (!privateKey) return null;

    const encoded = new TextEncoder().encode(canonicalizePayload(payload));
    const sigBuffer = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      encoded
    );
    return btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
      .replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=/g, "");
  } catch (e) {
    console.error("Payload signing failed:", e);
    return null;
  }
}

// Converts ASN.1 DER ECDSA signature (Go output) to IEEE P1363 (WebCrypto input).
function derToP1363(der) {
  var off = 2;
  if (der[1] === 0x81) off = 3;
  off++;
  var rLen = der[off++];
  var rPad = (rLen === 33 && der[off] === 0x00) ? 1 : 0;
  var rBytes = der.slice(off + rPad, off + rLen);
  off += rLen;
  off++;
  var sLen = der[off++];
  var sPad = (sLen === 33 && der[off] === 0x00) ? 1 : 0;
  var sBytes = der.slice(off + sPad, off + sLen);
  var result = new Uint8Array(64);
  result.set(rBytes.slice(-32), 32 - Math.min(rBytes.length, 32));
  result.set(sBytes.slice(-32), 64 - Math.min(sBytes.length, 32));
  return result;
}

// Verifies the server-side ECDSA-SHA256 signature against the payload.
async function verifySSS(payload, sssBase64Url, pemPublicKey) {
  try {
    let b64 = pemPublicKey
      .replace(/-----BEGIN PUBLIC KEY-----/g, '')
      .replace(/-----END PUBLIC KEY-----/g, '')
      .replace(/\s+/g, '')
      .replace(/[^A-Za-z0-9+/=]/g, '');
    while (b64.length % 4 !== 0) { 
        b64 += '=';
    }
    var der = Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
    var pubKey = await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    var data = new TextEncoder().encode(canonicalizePayload(payload));
    var sigB64 = sssBase64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (sigB64.length % 4) sigB64 += "=";
    var derBytes = Uint8Array.from(atob(sigB64), function(c) { return c.charCodeAt(0); });
    var p1363 = derToP1363(derBytes);
    var result = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, p1363, data);
    return result;
  } catch (e) {
    return false;
  }
}
function buildFinalConsentRequest(selectedLang) {
  const requestList = [];
  const consentDiv = document.getElementById("consent-root");

  const allElements = consentDiv.querySelectorAll("[name]");

  const pushConsent = (permissionId, optionId = null, hasValue = false) => {
    let existing = requestList.find(r => r.permissionId === permissionId);

    if (existing) {
      if (hasValue) {
        existing.optedForIndexes.push(parseInt(optionId));
      }
    } else {
      requestList.push({
        consentLanguage: selectedLang,
        consentReceivedType: receivedType,
        customAttributes,
        permissionId,
        optedForIndexes: hasValue ? [parseInt(optionId)] : []
      });
    }
  };

  allElements.forEach(el => {
    const permissionId = el.name;

    if (el.type === "checkbox" && enableCheckboxes) {
      if (el.checked) {
        pushConsent(permissionId, el.getAttribute("data-option-id") || "0", true);
      } else {
        pushConsent(permissionId, null, false);
      }
    }

    else if (el.type === "radio" && enableRadioButtons) {
      if (el.checked) {
        pushConsent(permissionId, el.getAttribute("data-option-id") || "0", true);
      } else {
        // ensure permission exists even if nothing selected
        pushConsent(permissionId, null, false);
      }
    }

  else if (el.tagName === "SELECT" && enableDropdowns) {
    const opt = el.options[el.selectedIndex];

    if (opt && opt.value !== "") {
      pushConsent(
        permissionId,
        opt.getAttribute("data-option-id") || "0",
        true
      );
    }
  }
  });

requestList.sort((a, b) =>
  String(a.permissionId).localeCompare(String(b.permissionId))
);

const normalizedList = requestList.map(item => {
  const sortedItem = {};
  Object.keys(item)
    .sort()
    .forEach(key => {
      sortedItem[key] = item[key];
    });
  return sortedItem;
});

return {
  createConsentRequestDtoWrapper: normalizedList
};
}

// Called on every radio/checkbox/dropdown change.
async function onSelectionChange(selectedLang) {

  const request = buildFinalConsentRequest(selectedLang);

  // Always track the latest snapshot so stale in-flight responses fail verification.
  currentSnapshot = request;
  var bssPublicKey = await getPublicKeyB64();
  var bss = await signPayload(currentSnapshot.createConsentRequestDtoWrapper);
  if (!bss || !bssPublicKey) {
   return; }

  try {
    var headers = { "Content-Type": "application/json", "Authorization": userToken || "" };

    var res = await fetch(signatureServiceUrl + "/v1/sign", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ payload: currentSnapshot.createConsentRequestDtoWrapper, bss: bss, bss_pkey: bssPublicKey })
    });
    if (!res.ok) {
      var signErr = null;
      try { signErr = await res.json(); } catch (e) {}
      if (res.status === 401) showToast(" 401 Unauthorized", "error");
      else if (res.status === 404) showToast(" 404 Not Found", "error");
      else if (res.status === 500) showToast(" 500 Service Down", "error");
      else if (signErr?.error?.code === "BSS_VERIFICATION_FAILED") showToast(" BSS authentication failed", "error");
      else if (signErr?.error?.code === "SSS_VERIFICATION_FAILED") showToast(" SSS authentication failed", "error");
      else showToast(" Signature service failed", "error");
      return;
    }
    var signData = await res.json();
    var sss = signData.sss;
    globalSSS = sss;
	
    // Verify against currentSnapshot (latest) — if user changed selection while
    // this request was in-flight, currentSnapshot !== snapshot and verification fails.
    var valid = await verifySSS(currentSnapshot.createConsentRequestDtoWrapper, sss, signData.sss_pkey);

    const submitBtn = document.getElementById("submitBtn");
    if (valid) {
      //storedSigning = { bss: bss, bssPublicKey: bssPublicKey, sss: sss };
      isSSSValid = true;
      if (submitBtn) submitBtn.disabled = false;
    } else {
      isSSSValid = false;
      if (submitBtn) submitBtn.disabled = true;
    }
  } catch (e) {
    console.error("[SDP-SIGN] Signature service call failed:", e);
    showToast("v1/sign service unavailable", "error");
  }
}


async function handleApiResponse(res) {
  let payload = {};

  if (res.status === 401) {
    const root = document.getElementById("consent-root");
    root.innerText = "401 UNAUTHORIZED";

    throw new Error("UNAUTHORIZED");
  }

  try {
    payload = await res.json();
  } catch (e) {}

  if (payload?.statusCode === 401) {
    const root = document.getElementById("consent-root");
    root.innerText = "401 UNAUTHORIZED";

    throw new Error("UNAUTHORIZED");
  }

  if (!res.ok) {
    const msg =
      payload?.statusMessage ||
      payload?.message ||
      "Request failed";

    showToast(msg, "error");
    throw new Error(msg);
  }

  return payload;
}

function setFormDisabled(disabled = true) {
  const root = document.getElementById("consent-root");
  const inputs = root.querySelectorAll("input, select, textarea, button");
  inputs.forEach(input => input.disabled = disabled);

  const submitBtn = document.getElementById("submitBtn");
  const cancelBtn = document.getElementById("cancelBtn");
  
  if (disabled) {
    submitBtn.classList.add("loading");
  } else {
    submitBtn.classList.remove("loading");
  }
}

const historyPagination = {
  page: 0,
  size: 10,
  hasMore: true,
  loading: false
};

const SCROLL_THRESHOLD = 180; 
function attachHistoryScroll() {
  const scrollContainer = document.querySelector(".preview-statements");

  if (!scrollContainer || scrollContainer.dataset.scrollBound) return;

  scrollContainer.addEventListener("scroll", () => {
    if (
      scrollContainer.scrollTop + scrollContainer.clientHeight >=
      scrollContainer.scrollHeight - SCROLL_THRESHOLD
    ) {
      loadMoreHistory();
    }
  });

  scrollContainer.dataset.scrollBound = "true";
}


async function loadMoreHistory() {
  if (!historyPagination.hasMore || historyPagination.loading) return;

  historyPagination.loading = true;
  historyPagination.failed = false;;

  try {
    const scrollPayload = {
      preferenceFormId,
      page: historyPagination.page + 1,
      pageSize: historyPagination.size,
      sortBy: "formName",
      sortDirection: "ASC"
    };
    const browserSignature = await signPayload(scrollPayload);
    if (browserSignature) scrollPayload.bss = browserSignature;

 const res = await fetch(preferenceHistoryApiUrl, {
  method: "POST",
  headers: authHeaders(),
  body: JSON.stringify(scrollPayload)
});


   const result = await handleApiResponse(res);
   const response = result.response;

  if (!response || !response.preferenceHistoryByTimeStamp) {
    historyPagination.hasMore = false;
    return;
  }
    Object.entries(response.preferenceHistoryByTimeStamp || {}).forEach(
      ([timestamp, list]) => {
        if (!window.preferenceHistory[timestamp]) {
          window.preferenceHistory[timestamp] = [];
        }
        window.preferenceHistory[timestamp].push(...list);
      }
    );

    historyPagination.page = response.page;
    historyPagination.hasMore = response.hasMore;

    renderHistory(window.preferenceHistory);
  } catch (e) {
    console.error("History scroll failed", e);

    // STOP infinite retry loop
    historyPagination.hasMore = false;
    historyPagination.failed = true;

  } finally {
    historyPagination.loading = false;
  }
}


document.addEventListener("DOMContentLoaded", () => {
  const container = document.querySelector(".widget-container");
  Array.from(container.children).forEach((child) => {
    if (!child.classList.contains("preview-statements")) {
      child.style.display = "none"; 
    }
  });

  const consentRoot = document.getElementById("consent-root");
  consentRoot.innerText = "Loading...";
});


function getSelectedByPosition(perm, selectedLang) {
  if (!perm.optedFor?.length || !perm.permissionTranslation) return [];

  const baseTr = perm.permissionTranslation[0];
  const targetTr = perm.permissionTranslation.find(
    pt => pt.language?.toLowerCase() === selectedLang
  );

  if (!baseTr?.options || !targetTr?.options) return [];

  return perm.optedFor
    .map(value => {
      const idx = baseTr.options.indexOf(value);
      return idx >= 0 ? targetTr.options[idx] : null;
    })
    .filter(Boolean);
}


function renderLanguageDropdown(data) {
  const langWrapper = document.getElementById("language-wrapper");
  const langSelect = document.getElementById("langSelect");

  const languages = (data.languages || []).map(l => l.toLowerCase());

  if (!showLanguageDropdown || languages.length === 0) {
    langWrapper.style.display = "none";
    return;
  }

  langWrapper.style.display = "block";
  langSelect.innerHTML = "";
  selectedLanguage = selectedLanguage || languages[0];

  languages.forEach(lang => {
    const opt = document.createElement("option");
    opt.value = lang;
    opt.text = lang.toUpperCase();
    if (lang === selectedLanguage) opt.selected = true;
    langSelect.appendChild(opt);
  });

	langSelect.onchange = async () => {
	  selectedLanguage = langSelect.value;

	  const request = buildFinalConsentRequest(selectedLanguage);

	  if (window.preferenceData?.currentPreference) {
		renderConsent(window.preferenceData, selectedLanguage);
	  }

	  if (!document.getElementById("historyTab").classList.contains("hidden")) {
		renderHistory(window.preferenceHistory, selectedLanguage);
	  }

	  await onSelectionChange(selectedLanguage, request);
	};
}


async function fetchConsentData() {
  try {
    const publicKey = await getPublicKeyB64();
    const browserSignature = await signPayload({ preferenceFormId });
    const baseBody = {
      preferenceFormId,
      page: 0,
      pageSize: 10,
      sortBy: "formName",
      sortDirection: "ASC",
    };
    if (publicKey) baseBody.bssk = publicKey;
    const res = await fetch(preferenceDetailsApiUrl, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(baseBody),
    });

const result = await handleApiResponse(res);
consentJwt = result.response.payload;
// decode JWT response
const decoded = decodeJwt(result.response.payload);
const data = decoded?.data?.response?.data;

// NEW LINES YOU NEED TO ADD:
const sssk = decoded.sssk;
const bssk = decoded.bssk;
const nonce = decoded.nonce;

window.preferenceHistory = data.preferenceHistoryAgainstTimeStamp?.preferenceHistoryByTimeStamp || {};
data.currentPreference.permissions =
  (data.currentPreference?.permissions || [])
    .map(p => ({ ...p }))
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));

window.preferenceData = data;
 if (data.golabalFontFamily) {
  const fontFamily = data.golabalFontFamily;
  if (!document.getElementById("consent-global-font")) {
    const style = document.createElement("style");
    style.id = "consent-global-font";
    style.innerHTML = `
      .widget-container input,
      .widget-container select,
      .widget-container textarea,
      .widget-container button,
  `;
    document.head.appendChild(style);
  }
}

// keep previously selected language after submit
selectedLanguage = selectedLanguage || data.languages?.[0]?.toLowerCase() || "englis";
renderLanguageDropdown(data);
handlePreferenceView(data.preferenceView);
if (data.currentPreference) {
  renderConsent(data, selectedLanguage);
    setTimeout(() => {
  onSelectionChange(selectedLanguage);
}, 0);
}

renderConsent(data, selectedLanguage);
    const container = document.querySelector(".widget-container");
    Array.from(container.children).forEach((child) => {
      child.style.display = "";
    });

  } catch (e) {
      console.error(e);

  }
}

function showToast(message, type) {
  const toast = document.getElementById("toast");

  toast.textContent = message;
  toast.style.backgroundColor =
    type === "success" ? "#4CAF50" : "#f44336";

  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2000);
}


function getFormValues(selectedLang) {
  createConsentRequestList = [];

  const consentDiv = document.getElementById("consent-root");
  const checkboxes = consentDiv.querySelectorAll('input[type="checkbox"]:checked');
  const radioButtons = consentDiv.querySelectorAll('input[type="radio"]:checked');
  const dropdowns = consentDiv.querySelectorAll("select");

  const pushConsent = (permissionId, optionId) => {
    let existing = createConsentRequestList.find(req => req.permissionId === permissionId);
    if (existing) {
      existing.optedForIndexes.push(parseInt(optionId));
    } else {
      createConsentRequestList.push({
        permissionId,
        customAttributes,
        consentReceivedType: receivedType,
        optedForIndexes: [parseInt(optionId)],
        consentLanguage: selectedLang
      });
    }
  };

  checkboxes.forEach(checkbox => {
    if (!enableCheckboxes) return;
    const optionId = checkbox.getAttribute("data-option-id") || "0";
    pushConsent(checkbox.name, optionId);
  });

  radioButtons.forEach(radio => {
    if (!enableRadioButtons) return;
    const optionId = radio.getAttribute("data-option-id") || "0";
    pushConsent(radio.name, optionId);
  });


  dropdowns.forEach(drop => {
    if (!enableDropdowns) return;

    const selected = drop.options[drop.selectedIndex];

    // Skip unselected dropdown
    if (!selected || !selected.value) return;

    const optionId = selected.getAttribute("data-option-id") || "0";
    pushConsent(drop.name, optionId);
  });

  document.querySelectorAll("#consent-root [name]").forEach(el => {

    if (el.tagName === "SELECT") {
      return;
    }

    if (!createConsentRequestList.some(req => req.permissionId === el.name)) {
      createConsentRequestList.push({
        customAttributes,
        permissionId: el.name,
        consentReceivedType: receivedType,
        optedForIndexes: [],
        consentLanguage: selectedLang
      });
    }
  });

  sendConsent();
}
  
async function sendConsent() {
  setFormDisabled(true);
  try {
    createConsentRequestList.sort((a, b) =>
  String(a.permissionId).localeCompare(String(b.permissionId))
);
    const body = { createConsentRequestDtoWrapper: createConsentRequestList };
  console.log("request body:",JSON.stringify(body));
    if (storedSigning.bss) {
      body.bss = await signPayload(createConsentRequestList);
      body.sss = globalSSS;
      body.jwt=consentJwt;
    } else {
      const browserSignature = await signPayload(createConsentRequestList);
      if (browserSignature) body.bss = browserSignature;
      body.sss = globalSSS;
      body.jwt=consentJwt;
    }

    const encryptedPayload = await encryptPayload(body);
    const res = await fetch(submitApiUrl, {
      method: "POST",
      //headers: authHeaders(),
      //body: JSON.stringify(body)
      headers: { "Content-Type": "application/json", "Authorization": userToken || "" },
      body: JSON.stringify({ payload: encryptedPayload })
    });
    const data = await res.json();
    try {
      sessionStorage.setItem("consentResponse", JSON.stringify(data));
    } catch (e) {
      console.error("Storage failed:", e);
    }
    if (data.response && data.statusCode === 200) {
      showToast("Consent saved successfully!", "success");
	   setFormDisabled(false)
	   fetchConsentData()
     return data;
    } else {
      showToast(data.statusMessage || "Something went wrong.", "error");
      setFormDisabled(false);
      fetchConsentData()
    }
  } catch (err) {
    console.error(err);
    showToast("Failed to submit. Please check your network connection.", "error");
    setFormDisabled(false);
  } finally {
    // Send response to Android WebView if available
    if (typeof window.AndroidBridge !== 'undefined' && 
        typeof window.AndroidBridge.onApiResponse === 'function') {
      try {
        window.AndroidBridge.onApiResponse(JSON.stringify(data));
      } catch (error) {
        console.error('Failed to send response to Android:', error);
      }
    }
  }
}



function isOptionSelected(perm, optionId, baseValue) {
  const optedMap = perm.optedFor || {};

  if (Object.keys(optedMap).length > 0) {
    return !!optedMap[optionId];
  }

  return (perm.optedFor || []).includes(baseValue);
}


function renderConsent(data, selectedLang) {
  const root = document.getElementById("consent-root");
  root.innerHTML = "";

  const errorDiv = document.getElementById("error-message");
  errorDiv.innerHTML = "";

  const branding = data.currentPreference?.branding || {};
  const permissions = data.currentPreference?.permissions || [];

  const logoArea = document.getElementById("logo-area");
  logoArea.innerHTML = "";
  logoArea.classList.remove("left", "center", "right");

  const align = (branding.logoAlignment || "left").toLowerCase();
  logoArea.classList.add(["left", "center", "right"].includes(align) ? align : "left");

  const wrapper = document.createElement("div");
  wrapper.style.display = "flex";

  if (align === "center") {
    wrapper.style.flexDirection = "column";
  } else if (align === "right") {
    wrapper.style.flexDirection = "row-reverse";
  } else {
    wrapper.style.flexDirection = "row";
  }

  wrapper.style.alignItems = "center";
  wrapper.style.gap = "5px";


  if (branding.logo) {
    const img = document.createElement("img");
    img.src = branding.logo;
    img.alt = branding.companyName || "Logo";
    img.className = "branding-logo";
    img.onerror = () => img.classList.add("hidden");
    wrapper.appendChild(img);
  }

  if (branding.companyName) {
    const nameDiv = document.createElement("div");
    nameDiv.innerText = branding.companyName;
    nameDiv.classList.add("company-name");

    if (branding.headerFontColor)
      nameDiv.style.color = branding.headerFontColor;
    if (branding.headerFontFamily)
      nameDiv.style.fontFamily = branding.headerFontFamily;
    if (branding.headerFontSize) {
      const sizeMap = {
        small: "14px",
        medium: "16px",
        large: "20px",
      };
      const sz = branding.headerFontSize.toLowerCase();
      nameDiv.style.fontSize =
        sizeMap[sz] || branding.headerFontSize;
    }
    if (branding.headerFontStyle) {
      const styleLower =
        branding.headerFontStyle.toLowerCase();
      if (styleLower.includes("italic"))
        nameDiv.style.fontStyle = "italic";
      if (styleLower.includes("bold"))
        nameDiv.style.fontWeight = "bold";
    }

    wrapper.appendChild(nameDiv);
  }

  logoArea.appendChild(wrapper);

 
  if (!permissions.length) {
    root.innerHTML = "<p>No consent items found.</p>";
    return;
  }

  permissions.forEach((perm) => {
  const block = document.createElement("div");
  block.className = "permission-block";

  const tr = perm.permissionTranslation?.find(
    (pt) => pt.language.toLowerCase() === selectedLang
  );

  const htmlString = (tr?.text || perm.text || "").trim();
  const tempDiv = document.createElement("div");
  tempDiv.innerHTML = htmlString;

  const children = Array.from(tempDiv.children);

  if (children.length > 0) {
    children.forEach((child) => {
      const el = document.createElement(child.tagName.toLowerCase());
      el.innerHTML = child.innerHTML;

      if (child.getAttribute("style")) {
        el.setAttribute("style", child.getAttribute("style"));
      }

      el.style.display = "block";
      el.style.margin = "2px 0";
      el.style.lineHeight = "1.4";

      block.appendChild(el);
    });

    if (perm.mandatory) {
      const lastChild = block.lastChild;
      lastChild.innerHTML += ' <span class="mandatory">*</span>';
    }
  } else {
    const p = document.createElement("p");
    p.textContent = htmlString.replace(/<[^>]*>/g, "").trim();

    if (perm.mandatory) {
      p.innerHTML += ' <span class="mandatory">*</span>';
    }

    block.appendChild(p);
  }
  const options = tr?.options || perm.options || [];
  const optionMap = perm.optionsMap || {};

  if (perm.elementType === "CHECKBOX" && enableCheckboxes) {
    if (Object.keys(optionMap).length > 0) {
      const mapEntries = Object.entries(optionMap);
      const translatedOptions = tr?.options || perm.options || [];
      mapEntries.forEach(([id, baseValue], index) => {
        const displayLabel = translatedOptions[index] || baseValue;
        const labelEl = document.createElement("label");
        const input = document.createElement("input");
        input.type = "checkbox";
        input.name = perm.id;
        input.value = baseValue;
        input.setAttribute("data-option-id", id);
        if (isOptionSelected(perm, id, baseValue)) input.checked = true;
        labelEl.appendChild(input);
        labelEl.append(" " + displayLabel);
        block.appendChild(labelEl);
      });
    } else {
      const selectedOptions = getSelectedByPosition(perm, selectedLang);
      options.forEach((opt) => {
        const label = document.createElement("label");
        const input = document.createElement("input");
        input.type = "checkbox";
        input.name = perm.id;
        input.value = opt;
        if (selectedOptions.includes(opt)) input.checked = true;
        label.appendChild(input);
        label.append(" " + opt);
        block.appendChild(label);
      });
    }
  }

  if (perm.elementType === "RADIOBUTTON" && enableRadioButtons) {
    if (Object.keys(optionMap).length > 0) {
      const mapEntries = Object.entries(optionMap);
      const translatedOptions = tr?.options || perm.options || [];
      mapEntries.forEach(([id, baseValue], index) => {
        const displayLabel = translatedOptions[index] || baseValue;
        const labelEl = document.createElement("label");
        const input = document.createElement("input");
        input.type = "radio";
        input.name = perm.id;
        input.value = baseValue;
        input.setAttribute("data-option-id", id);
        if (isOptionSelected(perm, id, baseValue)) input.checked = true;
        labelEl.appendChild(input);
        labelEl.append(" " + displayLabel);
        block.appendChild(labelEl);
      });
    } else {
      const selectedOptions = getSelectedByPosition(perm, selectedLang);
      options.forEach((opt) => {
        const label = document.createElement("label");
        const input = document.createElement("input");
        input.type = "radio";
        input.name = perm.id;
        input.value = opt;
        if (selectedOptions.includes(opt)) input.checked = true;
        label.appendChild(input);
        label.append(" " + opt);
        block.appendChild(label);
      });
    }
  }

  if (perm.elementType === "DROPDOWN" && enableDropdowns) {
    const select = document.createElement("select");
    select.name = perm.id;

    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.text = "Select options";
    defaultOption.disabled = true;

    const hasSelection =
      (Array.isArray(perm.optedFor) && perm.optedFor.length > 0) ||
      (perm.optedFor &&
        typeof perm.optedFor === "object" &&
        Object.keys(perm.optedFor).length > 0);

    defaultOption.selected = !hasSelection;

    select.appendChild(defaultOption);

    if (Object.keys(optionMap).length > 0) {
      const mapEntries = Object.entries(optionMap);
      const translatedOptions = tr?.options || perm.options || [];
      mapEntries.forEach(([id, baseValue], index) => {
        const option = document.createElement("option");
        option.value = baseValue;
        option.text = translatedOptions[index] || baseValue;
        option.setAttribute("data-option-id", id);
        if (isOptionSelected(perm, id, baseValue)) option.selected = true;
        select.appendChild(option);
      });
    } else {
      const selectedOptions = getSelectedByPosition(perm, selectedLang);
      options.forEach((opt) => {
        const option = document.createElement("option");
        option.value = opt;
        option.text = opt;
        if (selectedOptions.includes(opt)) option.selected = true;
        select.appendChild(option);
      });
    }

    block.appendChild(select);
  }

  block.querySelectorAll("input, select").forEach(function(el) {
    el.addEventListener("change", function() { onSelectionChange(selectedLang); });
  });
  root.appendChild(block);
});

 

  const cancelBtn = document.getElementById("cancelBtn");
  const submitBtn = document.getElementById("submitBtn");

  const selectedLanguage = selectedLang?.toLowerCase();
  const translatedBranding =
    branding.brandingTranslation?.find(
      (b) => b.language?.toLowerCase() === selectedLanguage
    );

  const submitLabel =
    translatedBranding?.primaryButtonLabel ||
    branding.primaryButtonLabel ||
    "Submit";
  const cancelLabel =
    translatedBranding?.secondaryButtonLabel ||
    branding.secondaryButtonLabel ||
    "Cancel";

  if (showButtons) {
    cancelBtn.style.display = "block";
    cancelBtn.innerText = cancelLabel;

    submitBtn.style.display = "block";
    submitBtn.innerText = submitLabel;
    submitBtn.disabled = !isSSSValid;

      submitBtn.style.backgroundColor =
        branding.primaryButtonbgColor;
    if (branding.primaryFontColor)
      submitBtn.style.color = branding.primaryFontColor;
    if (branding.primaryButtonborderColor)
      submitBtn.style.borderColor =
        branding.primaryButtonborderColor;
    if (branding.primaryFontSize)
      submitBtn.style.fontSize = branding.primaryFontSize;
    if (branding.primaryFontStyle) {
      submitBtn.style.fontStyle =
        branding.primaryFontStyle;
      submitBtn.style.fontWeight =
        branding.primaryFontStyle;
    }

    if (branding.secondaryButtonBgColor)
      cancelBtn.style.backgroundColor =
        branding.secondaryButtonBgColor;
    if (branding.secondaryFontColor)
      cancelBtn.style.color =
        branding.secondaryFontColor;
    if (branding.secondaryButtonBorderColor)
      cancelBtn.style.borderColor =
        branding.secondaryButtonBorderColor;
    if (branding.secondaryFontSize)
      cancelBtn.style.fontSize =
        branding.secondaryFontSize;
    if (branding.secondaryFontStyle) {
      cancelBtn.style.fontStyle =
        branding.secondaryFontStyle;
      cancelBtn.style.fontWeight =
        branding.secondaryFontStyle;
    }

    const buttonGroup =
      document.getElementById("button-group");
    const buttonFooterAlignment =
      data.currentPreference.branding?.footerAlignment ||
      footerAlignment;

    buttonGroup.classList.remove("left", "center", "right");

    if (buttonFooterAlignment === "center") {
      buttonGroup.classList.add("center");
    } else if (buttonFooterAlignment === "right") {
      buttonGroup.classList.add("right");
    } else {
      buttonGroup.classList.add("left");
    }
  } else {
    cancelBtn.style.display = "none";
    submitBtn.style.display = "none";
  }

  submitBtn.onclick = () => {
    errorDiv.innerHTML = "";
    let isValid = true;

    permissions.forEach((perm) => {
      if (perm.mandatory) {
        const name = perm.id;
        let hasValue = false;

        if (
          perm.elementType === "CHECKBOX" ||
          perm.elementType === "RADIOBUTTON"
        ) {
          const inputs = root.querySelectorAll(
            `input[name="${name}"]:checked`
          );
          if (inputs.length > 0) hasValue = true;
        } else if (perm.elementType === "DROPDOWN") {
          const select = root.querySelector(
            `select[name="${name}"]`
          );
          if (select && select.value) hasValue = true;
        }

        if (!hasValue) {
          isValid = false;
          const error = document.createElement("div");
          error.className = "error-message";
          error.textContent = "This field is required.";
          errorDiv.appendChild(error);

          const inputs = root.querySelectorAll(
            `[name="${name}"]`
          );
          inputs.forEach((el) =>
            el.classList.add("error-border")
          );
        }
      }
    });

    if (!isValid) {
      showToast(
        "Please fill all mandatory fields",
        "error"
      );
      return;
    }

getFormValues(selectedLanguage);
  };

cancelBtn.onclick = async () => {
  if (window.preferenceData?.currentPreference) {
    // Reset form to original state
    renderConsent(window.preferenceData, selectedLanguage);

    // Clear previous signature state
    globalSSS = null;
    isSSSValid = false;

    const submitBtn = document.getElementById("submitBtn");
    if (submitBtn) {
      submitBtn.disabled = true;
    }

    // Generate fresh BSS + SSS for restored selections
    await onSelectionChange(selectedLanguage);
  }
};
}

function switchToCurrent() {
  document
    .getElementById("consent-root")
    .classList.remove("hidden");
  document
    .getElementById("historyTab")
    .classList.add("hidden");

  document
    .getElementById("tab-current")
    .classList.add("active");
  document
    .getElementById("tab-history")
    .classList.remove("active");

  document.getElementById("logo-area").style.display =
    "block";
  toggleFooterButtons(true);

    if (window.preferenceData?.currentPreference) {
    renderConsent(window.preferenceData, selectedLanguage);
  }
}

function switchToHistory() {
  document
    .getElementById("consent-root")
    .classList.add("hidden");
  document
    .getElementById("historyTab")
    .classList.remove("hidden");

  document
    .getElementById("tab-current")
    .classList.remove("active");
  document
    .getElementById("tab-history")
    .classList.add("active");
	
  

  document.getElementById("logo-area").style.display =
    "none";
  toggleFooterButtons(false);

if (window.preferenceHistory) {
  renderHistory(window.preferenceHistory, selectedLanguage);
}
  attachHistoryScroll();

}

function handlePreferenceView(view) {
  const tabs = document.getElementById("pc-tabs");
  const tabCurrent = document.getElementById("tab-current");
  const tabHistory = document.getElementById("tab-history");

  tabs.classList.add("d-none");

  if (view === "CURRENT_PREFERENCE") {
    tabs.classList.remove("d-none");
    tabHistory.style.display = "none";
    tabCurrent.style.display = "block";
    tabCurrent.classList.remove("pc-tab");
    tabCurrent.style.fontWeight = "bold"; 
    switchToCurrent();
  }

  if (view === "PREFERENCE_HISTORY") {
    tabs.classList.remove("d-none");
    tabCurrent.style.display = "none";
    tabHistory.style.display = "block";
    tabHistory.classList.remove("pc-tab");
    tabHistory.style.fontWeight = "bold"; 
    switchToHistory();
  }

  if (view === "BOTH") {
    tabs.classList.remove("d-none");
    tabCurrent.style.display = "block";
    tabHistory.style.display = "block";
    switchToCurrent();
  }
}

function toggleFooterButtons(show) {
  const cancelBtn = document.getElementById("cancelBtn");
  const submitBtn = document.getElementById("submitBtn");
  const footer = document.getElementById("button-group");
  const footerBorder = document.getElementById("full-width-footer-border");
  
  if (!show) {
    cancelBtn.style.display = "none";
    submitBtn.style.display = "none";
    footer.style.display = "none";
    footerBorder.classList.add("hidden"); 
  } else {
    footer.style.display = "flex";
    cancelBtn.style.display = "block";
    submitBtn.style.display = "block";
    footerBorder.classList.remove("hidden");
  }
  
}

function renderHistory(historyDto, selectedLang = "en") {
  const historyRoot = document.getElementById("historyTab");
  historyRoot.innerHTML = "";
  historyRoot.classList.add("history-scroll");

  if (!historyDto || Object.keys(historyDto).length === 0) {
    historyRoot.innerHTML = "<p>No preference history available.</p>";
    return;
  }

  Object.keys(historyDto)
    .sort((a, b) => new Date(b) - new Date(a))
    .forEach((timestamp) => {
      const record = document.createElement("div");
      record.className = "history-record";

      
      const dateHeader = document.createElement("div");
      dateHeader.className = "history-date";
      const date = new Date(timestamp);
      const datePart = date.toLocaleDateString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
      });

const timePart = date.toLocaleTimeString("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const icon = document.createElement("i");
icon.className = "ri-calendar-2-line me-2 fs-5 big-icon";


dateHeader.innerHTML = "";
dateHeader.appendChild(icon);
dateHeader.append(" ", datePart, " | ", timePart);

      record.appendChild(dateHeader);

const row = document.createElement("div");
  historyDto[timestamp].forEach(item => {
    const line = document.createElement("div");
    line.className = "history-row";
const tempDiv = document.createElement("div");
tempDiv.innerHTML = item.permission || "";

const children = Array.from(tempDiv.children);

const optedText = item.optedFor?.length
  ? item.optedFor
      .map(opt => opt.charAt(0).toUpperCase() + opt.slice(1))
      .join(", ")
  : "No selection";

if (children.length > 0) {
  children.forEach((child, index) => {
    const cloned = document.createElement(child.tagName.toLowerCase());
    cloned.innerHTML = child.innerHTML;

    cloned.style.display = "block";
    cloned.style.margin = "2px 0";
    cloned.style.lineHeight = "1.4";

    if (child.getAttribute("style")) {
      cloned.setAttribute("style", child.getAttribute("style"));
    }

    if (index === children.length - 1) {
      cloned.innerHTML += ` : <span class="value">${optedText}</span>`;
    }

    line.appendChild(cloned);
  });
} else {
  line.innerHTML = `${item.permission} : <span class="value">${optedText}</span>`;
}
    row.appendChild(line);
  });

  record.appendChild(row);
  historyRoot.appendChild(record);
    });
}




document.getElementById("tab-current").addEventListener("click", switchToCurrent);
document.getElementById("tab-history").addEventListener("click", switchToHistory);

function decodeJwt(token) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );

  return JSON.parse(jsonPayload);
}



async function submitConsent() {
  return await sendConsent();
}

function resetConsent() {
  resetWidget();
}

function getConsentState() {
  return {
    payload: createConsentRequestList,
    jwt: consentJwt,
    sss: globalSSS
  };
}
async function resetWidget() {
  if (window.preferenceData?.currentPreference) {
    // Restore original state
    renderConsent(window.preferenceData, selectedLanguage);

    // Clear old signature
    globalSSS = null;
    isSSSValid = false;

    const submitBtn = document.getElementById("submitBtn");
    if (submitBtn) {
      submitBtn.disabled = true;
    }

    // Generate fresh BSS + SSS
    await onSelectionChange(selectedLanguage);
  }
}

window.consentWidget = {
  submit: async () => {
    try {
      const langSelect = document.getElementById("langSelect");

      const selectedLang =
        langSelect?.value ||
        document.documentElement.lang ||
        "en";

      const payload = buildFinalConsentRequest(selectedLang);

      // IMPORTANT: ensure we don't send empty payload
      if (!payload?.createConsentRequestDtoWrapper?.length) {
        return {
          success: false,
          error: "Empty consent selection"
        };
      }

      createConsentRequestList = payload.createConsentRequestDtoWrapper;

      const result = await sendConsent();

      return {
        success: true,
        data: result
      };

    } catch (err) {
      return {
        success: false,
        error: err.message
      };
    }
  },

  reset: () => resetWidget()
};

  
initSigningKey().then(fetchConsentData);

