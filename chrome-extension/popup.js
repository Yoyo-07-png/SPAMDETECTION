const GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me";
const ANALYSIS_API = "http://127.0.0.1:8000/analyze";
const searchForm = document.querySelector("#search-form");
const searchButton = document.querySelector("#search-button");
const analyzeOpenButton = document.querySelector("#analyze-open-button");
const searchQuery = document.querySelector("#search-query");
const statusMessage = document.querySelector("#status");
const messageList = document.querySelector("#messages");
const report = document.querySelector("#report");

analyzeOpenButton.addEventListener("click", analyzeOpenEmail);
searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  searchMessages();
});

function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      if (!token) {
        reject(new Error("Google did not return an access token."));
        return;
      }
      resolve(token);
    });
  });
}

function getActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      if (!tabs[0]) {
        reject(new Error("Could not find the active browser tab."));
        return;
      }
      resolve(tabs[0]);
    });
  });
}

function getOpenMessageIds(tabId) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: () => {
          const isVisible = (element) => {
            const style = getComputedStyle(element);
            return (
              element.getClientRects().length > 0 &&
              style.visibility !== "hidden" &&
              style.display !== "none"
            );
          };

          return [...document.querySelectorAll("[data-legacy-message-id]")]
            .filter((element) => isVisible(element) && element.querySelector(".a3s"))
            .map((element) => element.getAttribute("data-legacy-message-id"))
            .filter(Boolean);
        },
      },
      (results) => {
        const error = chrome.runtime.lastError;
        if (error) {
          reject(new Error(error.message));
          return;
        }
        resolve([...new Set(results?.[0]?.result || [])]);
      },
    );
  });
}

function isGmailTab(tabUrl) {
  let url;
  try {
    url = new URL(tabUrl);
  } catch {
    return false;
  }
  return url.hostname === "mail.google.com";
}

async function gmailRequest(token, path, parameters = {}) {
  const url = new URL(`${GMAIL_API}/${path}`);
  for (const [key, value] of Object.entries(parameters)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        url.searchParams.append(key, item);
      }
    } else {
      url.searchParams.set(key, value);
    }
  }

  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.message || `Gmail API request failed (${response.status}).`);
  }
  return data;
}

async function analyzeOpenEmail() {
  analyzeOpenButton.disabled = true;
  analyzeOpenButton.querySelector("span").textContent = "Analyzing…";
  statusMessage.textContent = "";
  report.hidden = true;

  try {
    const tab = await getActiveTab();
    if (!isGmailTab(tab.url || "") || tab.id === undefined) {
      throw new Error("Open a Gmail message first, then try again.");
    }

    const messageIds = await getOpenMessageIds(tab.id);
    if (!messageIds.length) {
      throw new Error("Could not find an open email in this Gmail tab.");
    }
    const token = await getAuthToken();
    const messages = await Promise.all(
      messageIds.map((id) =>
        gmailRequest(token, `messages/${encodeURIComponent(id)}`, {
          format: "metadata",
          metadataHeaders: ["Subject"],
        }),
      ),
    );
    const latestMessage = messages.reduce((latest, message) =>
      Number(message.internalDate) > Number(latest.internalDate) ? message : latest,
    );
    const subject = latestMessage.payload?.headers?.find(
      ({ name }) => name.toLowerCase() === "subject",
    )?.value;
    const rawMessage = await gmailRequest(
      token,
      `messages/${encodeURIComponent(latestMessage.id)}`,
      { format: "raw" },
    );
    const emlBlob = rawMessageToBlob(rawMessage.raw);
    const formData = new FormData();
    formData.append("eml", emlBlob, `${safeFilename(subject, latestMessage.id)}.eml`);

    const response = await fetch(ANALYSIS_API, {
      method: "POST",
      body: formData,
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.detail || `Analysis API request failed (${response.status}).`);
    }
    renderReport(result);
    statusMessage.textContent = "Analysis complete.";
  } catch (error) {
    statusMessage.textContent = `Could not analyze the open email: ${error.message}`;
  } finally {
    analyzeOpenButton.disabled = false;
    analyzeOpenButton.querySelector("span").textContent = "Analyze open email";
  }
}

async function searchMessages() {
  searchButton.disabled = true;
  statusMessage.textContent = "Searching Gmail...";

  try {
    const token = await getAuthToken();
    const query = searchQuery.value.trim() || "in:inbox";
    const results = await gmailRequest(token, "messages", {
      maxResults: "10",
      q: query,
    });
    const messages = await Promise.all(
      (results.messages || []).map(async ({ id }) => {
        const message = await gmailRequest(token, `messages/${encodeURIComponent(id)}`, {
          format: "metadata",
          metadataHeaders: ["From", "Subject", "Date"],
        });
        return message;
      }),
    );

    renderMessages(messages);
    statusMessage.textContent = messages.length
      ? `Found ${messages.length} email${messages.length === 1 ? "" : "s"}.`
      : "No matching emails found.";
  } catch (error) {
    statusMessage.textContent = `Could not search Gmail: ${error.message}`;
  } finally {
    searchButton.disabled = false;
  }
}

function renderMessages(messages) {
  messageList.replaceChildren();

  for (const message of messages) {
    const headers = Object.fromEntries(
      (message.payload?.headers || []).map(({ name, value }) => [name.toLowerCase(), value]),
    );
    const item = document.createElement("li");
    item.className = "message";

    const subject = document.createElement("div");
    subject.className = "message-subject";
    subject.textContent = headers.subject || "(No subject)";
    item.append(subject);

    const details = document.createElement("div");
    details.className = "message-detail";
    details.textContent = [headers.from, headers.date].filter(Boolean).join(" · ");
    item.append(details);

    if (message.snippet) {
      const snippet = document.createElement("div");
      snippet.className = "message-snippet";
      snippet.textContent = message.snippet;
      item.append(snippet);
    }

    const downloadButton = document.createElement("button");
    downloadButton.type = "button";
    downloadButton.textContent = "Download .eml";
    downloadButton.addEventListener("click", () => downloadMessage(message.id, headers.subject, downloadButton));
    item.append(downloadButton);
    messageList.append(item);
  }
}

async function downloadMessage(messageId, subject, button) {
  button.disabled = true;
  button.textContent = "Downloading...";

  try {
    const token = await getAuthToken();
    const message = await gmailRequest(token, `messages/${encodeURIComponent(messageId)}`, {
      format: "raw",
    });
    await saveRawMessage(message.raw, subject, messageId);
    statusMessage.textContent = "EML download started.";
  } catch (error) {
    statusMessage.textContent = `Could not download the email: ${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = "Download .eml";
  }
}

async function saveRawMessage(raw, subject, messageId) {
  const objectUrl = URL.createObjectURL(rawMessageToBlob(raw));

  try {
    await new Promise((resolve, reject) => {
      chrome.downloads.download(
        {
          url: objectUrl,
          filename: `${safeFilename(subject, messageId)}.eml`,
          saveAs: true,
        },
        (downloadId) => {
          const error = chrome.runtime.lastError;
          if (error) {
            reject(new Error(error.message));
            return;
          }
          if (downloadId === undefined) {
            reject(new Error("Chrome did not start the download."));
            return;
          }
          resolve(downloadId);
        },
      );
    });
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  } catch (error) {
    URL.revokeObjectURL(objectUrl);
    throw error;
  }
}

function rawMessageToBlob(raw) {
  const base64 = raw.replace(/-/g, "+").replace(/_/g, "/");
  const paddedBase64 = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(paddedBase64);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new Blob([bytes], { type: "message/rfc822" });
}

function renderReport(result) {
  report.replaceChildren();
  report.hidden = false;

  const title = document.createElement("h2");
  title.className = "report-title";
  title.textContent = result.subject || result.filename || "Email analysis";
  report.append(title);

  const finalScore = result.header_score?.FINAL_HEADER_SCORING;
  const score = document.createElement("p");
  score.className = "report-score";
  const highHeaderRisk = typeof finalScore === "number" && finalScore >= 2;
  score.dataset.risk = highHeaderRisk ? "high" : "low";
  score.textContent = typeof finalScore === "number"
    ? `Header risk score: ${finalScore.toFixed(1)}`
    : "Header risk score unavailable";

  const scoreDetails = Object.entries(result.header_score || {})
    .filter(([name]) => name !== "FINAL_HEADER_SCORING")
    .map(([name, value]) => `${name}: ${Number(value).toFixed(2)}`);
  const headerSection = document.createElement("section");
  headerSection.className = "report-header-section";
  headerSection.dataset.risk = highHeaderRisk ? "high" : "low";
  appendReportSection(headerSection, "Header scans", scoreDetails);
  headerSection.prepend(score);
  appendReportSection(headerSection, "Header findings", result.header_details || []);
  report.append(headerSection);

  const bodyAnalysis = result.body_analysis;
  if (typeof bodyAnalysis === "string") {
    const bodySection = createBodySection();
    appendReportSection(bodySection, "Body analysis", [bodyAnalysis]);
    report.append(bodySection);
  } else if (bodyAnalysis) {
    const bodySection = createBodySection();
    const overview = document.createElement("div");
    overview.className = "body-overview";
    overview.append(createSpamGauge(Number(bodyAnalysis.spam_probability)));

    const summary = document.createElement("div");
    summary.className = "body-summary";
    const bodyTitle = document.createElement("h3");
    bodyTitle.textContent = "Body analysis";
    summary.append(bodyTitle);
    for (const text of [
      `${bodyAnalysis.label} · ${Number(bodyAnalysis.confidence).toFixed(1)}% confidence`,
      `Ham likelihood: ${(Number(bodyAnalysis.ham_probability) * 100).toFixed(1)}%`,
      `Matched features: ${bodyAnalysis.matched_features}`,
    ]) {
      const line = document.createElement("p");
      line.textContent = text;
      summary.append(line);
    }
    overview.append(summary);
    bodySection.append(overview);

    appendReportSection(
      bodySection,
      "Words contributing toward spam",
      (bodyAnalysis.spam_evidence || []).map(formatEvidence),
    );
    appendReportSection(
      bodySection,
      "Words contributing toward ham",
      (bodyAnalysis.ham_evidence || []).map(formatEvidence),
    );
    report.append(bodySection);
  }

  function createBodySection() {
    const section = document.createElement("section");
    section.className = "report-body-section";
    return section;
  }

  function createSpamGauge(probability) {
    const gauge = document.createElement("div");
    gauge.className = "spam-gauge";
    gauge.setAttribute("role", "img");

    const svgNamespace = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNamespace, "svg");
    svg.setAttribute("viewBox", "0 0 100 100");
    svg.setAttribute("aria-hidden", "true");

    const track = document.createElementNS(svgNamespace, "circle");
    track.setAttribute("class", "spam-gauge-track");
    track.setAttribute("cx", "50");
    track.setAttribute("cy", "50");
    track.setAttribute("r", "44");

    const value = document.createElementNS(svgNamespace, "circle");
    value.setAttribute("class", "spam-gauge-value");
    value.setAttribute("cx", "50");
    value.setAttribute("cy", "50");
    value.setAttribute("r", "44");
    svg.append(track, value);
    gauge.append(svg);

    const label = document.createElement("span");
    label.className = "spam-gauge-label";
    const percentageText = document.createElement("span");
    percentageText.className = "spam-value";
    const caption = document.createElement("span");
    caption.className = "spam-caption";
    caption.textContent = "SPAM";
    label.append(percentageText, caption);
    gauge.append(label);

    if (Number.isFinite(probability)) {
      const percentage = Math.min(100, Math.max(0, probability * 100));
      gauge.dataset.level = percentage >= 50 ? "high" : "low";
      value.style.strokeDashoffset = String(276.46 * (1 - percentage / 100));
      percentageText.textContent = `${Math.round(percentage)}%`;
      gauge.setAttribute("aria-label", `Spam likelihood ${percentage.toFixed(1)} percent`);
    } else {
      percentageText.textContent = "—%";
      gauge.setAttribute("aria-label", "Spam likelihood unavailable");
    }
    return gauge;
  }

  function appendReportSection(parent, heading, items) {
    const section = document.createElement("section");
    section.className = "report-section";
    const sectionTitle = document.createElement("h3");
    sectionTitle.textContent = heading;
    section.append(sectionTitle);

    const list = document.createElement("ul");
    for (const item of items) {
      const listItem = document.createElement("li");
      listItem.textContent = item;
      if (heading === "Header findings") {
        const severity = item.match(/WARNING=(CRITICAL|HIGH|MODERATE|MEDIUM|LOW|NEUTRAL)/i)?.[1];
        if (severity) {
          listItem.dataset.severity = severity.toLowerCase();
        }
      }
      if (heading.includes("contributing")) {
        listItem.className = "report-evidence";
      }
      list.append(listItem);
    }
    if (!items.length) {
      const listItem = document.createElement("li");
      listItem.textContent = "No findings.";
      list.append(listItem);
    }
    section.append(list);
    parent.append(section);
  }

  function formatEvidence(item) {
    return `${item.term} (${Number(item.log_odds).toFixed(3)})`;
  }
}

function safeFilename(subject, messageId) {
  const cleaned = (subject || `gmail-message-${messageId}`)
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_")
    .replace(/[. ]+$/g, "")
    .trim()
    .slice(0, 120);
  return cleaned || `gmail-message-${messageId}`;
}
