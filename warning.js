const token = new URLSearchParams(window.location.search).get("token") || "";
const levelElement = document.querySelector("#level");
const continueButton = document.querySelector("#continue");
const reasonGroups = document.querySelector("#reason-groups");
let warningState = null;

const groupLabels = { url: "URL", page: "Página", reputation: "Reputação", integration: "Integração" };

function appendReasons(title, reasons) {
  if (!Array.isArray(reasons) || reasons.length === 0) return;
  const section = document.createElement("section");
  const heading = document.createElement("h3");
  heading.textContent = title;
  const list = document.createElement("ul");
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    list.append(item);
  }
  section.append(heading, list);
  reasonGroups.append(section);
}

function render(state) {
  warningState = state;
  document.querySelector("#destination").textContent = state.url;
  document.querySelector("#score").textContent = String(state.score);
  if (state.groupedReasons) {
    for (const [group, label] of Object.entries(groupLabels)) appendReasons(label, state.groupedReasons[group]);
  } else {
    appendReasons("Evidências", state.reasons);
  }
  if (state.externalReputation?.listed) {
    document.querySelector("#external-source").textContent = state.externalReputation.source || "base local";
    document.querySelector("#external-evidence").hidden = false;
  }
  if (state.level === "blocked") {
    levelElement.textContent = state.externalReputation?.listed ? "LISTADO EM BASE DE PHISHING" : "AMEAÇA CONFIRMADA";
    levelElement.classList.add("malicious");
    document.querySelector("#title").textContent = "Navegação bloqueada";
    continueButton.hidden = true;
  } else {
    levelElement.textContent = "SUSPEITO";
    document.querySelector("#title").textContent = "Este link apresenta sinais de risco";
  }
  document.querySelector("#loading").hidden = true;
  document.querySelector("#warning-content").hidden = false;
}

chrome.runtime.sendMessage({ type: "get-warning-state", token }).then((response) => {
  if (!response?.ok) throw new Error("Estado indisponível");
  render(response.state);
}).catch(() => {
  document.querySelector("#loading").hidden = true;
  document.querySelector("#warning-content").hidden = false;
  levelElement.textContent = "AVISO EXPIRADO";
  document.querySelector("#title").textContent = "Este aviso não pôde ser validado";
  document.querySelector("#destination").textContent = "O destino não foi recuperado.";
  continueButton.hidden = true;
});

document.querySelector("#back").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else window.close();
});

continueButton.addEventListener("click", () => {
  if (!warningState || warningState.level !== "suspicious") return;
  continueButton.disabled = true;
  chrome.runtime.sendMessage({ type: "continue-navigation-v4", token }).then((response) => {
    if (!response?.ok) continueButton.disabled = false;
  }).catch(() => { continueButton.disabled = false; });
});
