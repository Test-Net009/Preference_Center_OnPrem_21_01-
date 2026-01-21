const {
  preferenceFormId,
  preferenceDetailsApiUrl,
  preferenceHistoryApiUrl,
  submitApiUrl,
  userToken,
  dataPrincipalId,
  showButtons,
  showLanguageDropdown,
  enableCheckboxes,
  enableRadioButtons,
  enableDropdowns,
  footerAlignment = "left"
} = window.consentWidgetConfig;

let createConsentRequestList = [];
let dataPrincipalIdList = [];
let selectedLanguage = "en";

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": userToken || ""
  };
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
function getDataPrincipalId() {
  if (!dataPrincipalId?.key || !dataPrincipalId?.value) return null;

  return {
    key: dataPrincipalId.key,
    value: dataPrincipalId.value
  };
}

async function loadMoreHistory() {
  if (!historyPagination.hasMore || historyPagination.loading) return;

  historyPagination.loading = true;

  try {
 const res = await fetch(preferenceHistoryApiUrl, {
  method: "POST",
  headers: authHeaders(),
  body: JSON.stringify({
    preferenceFormId,
    page: historyPagination.page + 1,
    pageSize: historyPagination.size,
    sortBy: "formName",
    sortDirection: "ASC"
  })
});


   const result = await handleApiResponse(res);
const response = result.response;


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

  langSelect.onchange = () => {
    selectedLanguage = langSelect.value;

    if (!document.getElementById("consent-root").classList.contains("hidden")) {
      if (window.preferenceData?.currentPreference) {
        renderConsent(window.preferenceData, selectedLanguage);
      }
    }

    if (!document.getElementById("historyTab").classList.contains("hidden")) {
      renderHistory(window.preferenceHistory, selectedLanguage);
    }
  };
}


async function fetchConsentData() {
  try {
    const res = await fetch(preferenceDetailsApiUrl, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        preferenceFormId,
        page: 0,          
        pageSize: 10,      
        sortBy: "formName",       
        sortDirection: "ASC", 
      }),
    });

    const result = await handleApiResponse(res);
const data = result.response;

window.preferenceHistory = data.preferenceHistoryAgainstTimeStamp?.preferenceHistoryByTimeStamp || {};
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

selectedLanguage = data.languages?.[0]?.toLowerCase() || "en";
renderLanguageDropdown(data);
handlePreferenceView(data.preferenceView);
if (data.currentPreference) {
  renderConsent(data, selectedLanguage);
}

    renderConsent(data, data.languages?.[0]?.toLowerCase() || "en");
    const container = document.querySelector(".widget-container");
    Array.from(container.children).forEach((child) => {
      child.style.display = "";
    });

  } catch (e) {
      console.error(e);

  }
}

function setDataPrincipalIdList() {
  const { dataPrincipalId } = window.consentWidgetConfig || {};
  if (dataPrincipalId && dataPrincipalId.key && dataPrincipalId.value) {
    dataPrincipalIdList.push({
      key: dataPrincipalId.key,
      value: dataPrincipalId.value,
    });
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
  setDataPrincipalIdList();
  createConsentRequestList = [];

  const consentDiv = document.getElementById("consent-root");
  const checkboxes = consentDiv.querySelectorAll(
    'input[type="checkbox"]:checked'
  );
  const radioButtons = consentDiv.querySelectorAll(
    'input[type="radio"]:checked'
  );
  const dropdowns = consentDiv.querySelectorAll("select");

  checkboxes.forEach((checkbox) => {
    if (!enableCheckboxes) return;

    const label =
      checkbox.closest("label")?.textContent.trim() || checkbox.value;
    const permissionId = checkbox.name;
    let permissionFound = false;

    createConsentRequestList.find((o, i) => {
      if (o.permissionId === permissionId) {
        createConsentRequestList[i].optedFor.push(label);
        permissionFound = true;
        return true;
      }
      return false;
    });

    if (!permissionFound) {
      const request = {
        dataPrincipalIdList,
        permissionId,
        consentReceivedType: "FORMS",
        optedFor: [label],
        consentLanguage: selectedLang,
      };
      createConsentRequestList.push(request);
    }
  });

  radioButtons.forEach((radioButton) => {
    if (!enableRadioButtons) return;

    const label =
      radioButton.closest("label")?.textContent.trim() ||
      radioButton.value;
    const permissionId = radioButton.name;
    let permissionFound = false;

    createConsentRequestList.find((o, i) => {
      if (o.permissionId === permissionId) {
        createConsentRequestList[i].optedFor.push(label);
        permissionFound = true;
        return true;
      }
      return false;
    });

    if (!permissionFound) {
      const request = {
        dataPrincipalIdList,
        permissionId,
        consentReceivedType: "FORMS",
        optedFor: [label],
        consentLanguage: selectedLang,
      };
      createConsentRequestList.push(request);
    }
  });

  dropdowns.forEach((dropdown) => {
    if (!enableDropdowns) return;

    const selectedOption = dropdown.options[dropdown.selectedIndex];
    const permissionId = dropdown.name;
    let permissionFound = false;

    createConsentRequestList.find((o, i) => {
      if (o.permissionId === permissionId) {
        createConsentRequestList[i].optedFor.push(
          selectedOption.textContent
        );
        permissionFound = true;
        return true;
      }
      return false;
    });

    if (!permissionFound) {
      const request = {
        dataPrincipalIdList,
        permissionId,
        consentReceivedType: "FORMS",
        optedFor: [selectedOption.textContent],
        consentLanguage: selectedLang,
      };
      createConsentRequestList.push(request);
    }
  });

  const consentElements = document.querySelectorAll(
    "#consent-root [name]"
  );
  consentElements.forEach((element) => {
    const name = element.getAttribute("name");
    let permissionFound = false;

    createConsentRequestList.find((o) => {
      if (o.permissionId === name) {
        permissionFound = true;
        return true;
      }
      return false;
    });

    if (!permissionFound) {
      const request = {
        dataPrincipalIdList,
        permissionId: name,
        consentReceivedType: "FORMS",
        optedFor: [],
        consentLanguage: selectedLang,
      };
      createConsentRequestList.push(request);
    }
  });

  sendConsent();
}

async function sendConsent() {
  setFormDisabled(true);
  const errorDiv = document.getElementById("error-message");

  try {
    const res = await fetch(submitApiUrl, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        createConsentRequestDtoWrapper: createConsentRequestList,
      }),
    });

    const data = await handleApiResponse(res);

    if (data.response && data.statusCode === 200) {
      showToast("Consent saved successfully!", "success");
    } else {
      showToast(data.statusMessage || "Something went wrong.", "error");
    }

    setTimeout(() => window.location.reload(), 1500);
  } catch (err) {
    console.error(err);
    showToast("Failed to submit. Please check your network connection.", "error");
    setTimeout(() => window.location.reload(), 1500);
  } finally {
    setFormDisabled(false); 
  }
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
    // Add all children first
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

    // Append '*' to the **last child** if mandatory
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

  if (perm.elementType === "CHECKBOX" && enableCheckboxes) {
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

  if (perm.elementType === "RADIOBUTTON" && enableRadioButtons) {
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

  if (perm.elementType === "DROPDOWN" && enableDropdowns) {
    const select = document.createElement("select");
    select.name = perm.id;

    const selectedOptions = getSelectedByPosition(perm, selectedLang);

    options.forEach((opt) => {
      const option = document.createElement("option");
      option.value = opt;
      option.text = opt;

      if (selectedOptions.includes(opt)) option.selected = true;

      select.appendChild(option);
    });

    block.appendChild(select);
  }

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

    if (branding.primaryButtonbgColor)
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

  cancelBtn.onclick = () => {
    window.location.reload();
  };
}

fetchConsentData();

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

  if (!window.historyRendered && window.preferenceHistory) {
    renderHistory(window.preferenceHistory);
    window.historyRendered = true;
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
    .sort((a, b) => Number(b) - Number(a)) 
    .forEach((timestamp) => {
      const record = document.createElement("div");
      record.className = "history-record";

      
      const dateHeader = document.createElement("div");
      dateHeader.className = "history-date";
const date = new Date(Number(timestamp));

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

