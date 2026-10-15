function ex(value) {
  document.getElementById("url").value = value;
  document.getElementById("url").focus();
}

function setError(message) {
  document.getElementById("err").textContent = message || "";
}

function setRiskVisual(risk) {
  const ring = document.getElementById("scoreRing");
  const angle = Math.max(0, Math.min(100, Number(risk))) * 3.6;
  ring.style.background =
    `conic-gradient(#65e5ad 0deg, #65e5ad ${angle}deg, #172c25 ${angle}deg, #172c25 360deg)`;
}

function renderFeatures(features) {
  const box = document.getElementById("features");
  box.innerHTML = "";

  features.forEach(feature => {
    const item = document.createElement("div");
    item.className = `feature ${feature.status || ""}`;

    const name = document.createElement("span");
    name.textContent = feature.name;

    const value = document.createElement("b");
    value.textContent = feature.value;

    item.appendChild(name);
    item.appendChild(value);
    box.appendChild(item);
  });
}

function renderReasons(reasons) {
  const list = document.getElementById("reasons");
  list.innerHTML = "";

  reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    list.appendChild(li);
  });
}

function renderPositiveSignals(signals) {
  const box = document.getElementById("positiveBox");
  const list = document.getElementById("positive");
  list.innerHTML = "";

  if (!signals || signals.length === 0) {
    box.classList.add("hidden");
    return;
  }

  signals.forEach(signal => {
    const li = document.createElement("li");
    li.textContent = signal;
    list.appendChild(li);
  });

  box.classList.remove("hidden");
}

async function scan() {
  const input = document.getElementById("url");
  const result = document.getElementById("result");
  const button = document.querySelector(".scan-btn");
  const url = input.value.trim();

  setError("");

  if (!url) {
    setError("Please enter a URL.");
    input.focus();
    return;
  }

  const oldText = button.innerHTML;
  button.disabled = true;
  button.innerHTML = "Analyzing <span>…</span>";

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed.");
    }

    result.classList.remove("hidden");

    document.getElementById("label").textContent = data.label;
    document.getElementById("host").textContent = data.host;
    document.getElementById("summary").textContent =
      data.threat === "HIGH"
        ? "Multiple high-risk URL indicators were detected."
        : data.threat === "MEDIUM"
        ? "Several structural indicators deserve caution."
        : "No strong phishing indicators were detected in the URL structure.";

    document.getElementById("risk").textContent = data.risk;
    document.getElementById("threat").textContent = data.threat;
    document.getElementById("conf").textContent = data.confidence + "%";
    document.getElementById("proto").textContent = data.https ? "HTTPS" : "HTTP";
    document.getElementById("len").textContent = data.length + " chars";
    document.getElementById("analysisType").textContent = "HEURISTIC";
    document.getElementById("modelStatus").textContent = data.model_status;

    setRiskVisual(data.risk);
    renderFeatures(data.features || []);
    renderReasons(data.reasons || []);
    renderPositiveSignals(data.positive_checks || []);

    result.scrollIntoView({behavior: "smooth", block: "start"});
  } catch (error) {
    setError(error.message || "Analysis failed.");
  } finally {
    button.disabled = false;
    button.innerHTML = oldText;
  }
}

document.getElementById("url").addEventListener("keydown", event => {
  if (event.key === "Enter") scan();
});
