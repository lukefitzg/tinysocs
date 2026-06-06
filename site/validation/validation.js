/* TinySocs validation dashboard — vanilla JS, no framework.
   Fetches data/summary.json (built in CI by build_validation_summary.py)
   and renders the headline, the sortable per-rule table, and the coverage
   gap. All maths is precomputed server-side; this file only presents it. */

const CATEGORY_LABEL = {
  PASS: "Detected",
  MISS: "Missed",
  ERROR: "Error",
  SKIP_PLATFORM: "Skip (platform)",
  SKIP_PREREQ: "Skip (prereq)",
};

// Sort precedence for the "This week" column (most-alarming first when desc).
const CATEGORY_ORDER = {
  MISS: 0,
  ERROR: 1,
  SKIP_PREREQ: 2,
  SKIP_PLATFORM: 3,
  PASS: 4,
  null: 5,
};

const RESULTS_BASE =
  "https://github.com/lukefitzg/tinysocs/blob/main/results/";

let STATE = { rules: [], sortKey: "id", sortDir: 1, filter: "", onlyCovered: false };

document.addEventListener("DOMContentLoaded", init);

async function init() {
  const statusEl = document.getElementById("status");
  try {
    const res = await fetch("data/summary.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    statusEl.hidden = true;
    render(data);
  } catch (err) {
    statusEl.classList.add("error");
    statusEl.textContent =
      "Could not load validation data. This page is generated weekly — " +
      "if you're seeing this, the latest run may not have published yet.";
    console.error(err);
  }
}

function render(data) {
  renderHeadline(data);
  renderLegend();
  renderCoverage(data);
  STATE.rules = data.rules || [];
  STATE.weeks = data.weeks || [];
  wireControls();
  renderTable();
}

function renderHeadline(data) {
  const latest = data.latest || {};
  const s = latest.summary || {};
  const cov = data.coverage || {};

  document.getElementById("headline").hidden = false;
  document.getElementById("hl-week").textContent = "· " + (latest.iso_week || "");

  const passing = s.atomic_tests_detected ?? 0;
  const skipped = s.atomic_tests_skipped ?? 0;
  const missed = s.atomic_tests_missed ?? 0;
  const errored = s.atomic_tests_error ?? 0;

  document.getElementById("hl-counts").innerHTML =
    `<span class="num">${cov.rules_in_pack ?? "?"}</span> rules in pack` +
    sep() +
    `<span class="num">${cov.rules_with_test ?? "?"}</span> with Atomic Red Team coverage` +
    sep() +
    `<span class="num pass">${passing}</span> detected` +
    sep() +
    `<span class="num skip">${skipped}</span> skipped` +
    sep() +
    `<span class="num miss">${missed}</span> missed` +
    (errored ? sep() + `<span class="num">${errored}</span> error` : "");

  const p = latest.platform || {};
  const platformBits = [p.os, p.tinysocs_version ? "TinySocs " + p.tinysocs_version : null]
    .filter(Boolean)
    .join(" / ");
  const when = formatDate(latest.generated_at);
  const commit = latest.git_commit
    ? ` · commit <code>${escapeHtml(latest.git_commit)}</code>`
    : "";
  document.getElementById("hl-meta").innerHTML =
    `Last run: ${when}${commit}${platformBits ? " · " + escapeHtml(platformBits) : ""}`;

  // Download link to the raw per-week JSON on GitHub.
  const dl = document.getElementById("hl-download");
  dl.href = latest.iso_week ? RESULTS_BASE + latest.iso_week + ".json" : "#";

  renderBanner(latest, missed);
}

function renderBanner(latest, missed) {
  const banner = document.getElementById("hl-banner");
  if (missed > 0) {
    banner.hidden = false;
    banner.classList.add("miss");
    banner.innerHTML =
      `<strong>${missed} missed this run.</strong> A miss means a rule should have ` +
      `fired and didn't. We investigate every miss and publish a postmortem — ` +
      `see the per-rule table below and the linked notes.`;
    return;
  }
  if (latest.migrated) {
    banner.hidden = false;
    banner.innerHTML =
      "<strong>Backfilled historical snapshot.</strong> This run predates the " +
      "automated weekly pipeline — it's the last manual harness result, " +
      "preserved so the record starts honest. Live weekly runs replace it from here.";
    return;
  }
  // Staleness check: flag if the latest committed run is more than 8 days old.
  const ageDays = daysSince(latest.generated_at);
  if (ageDays !== null && ageDays > 8) {
    banner.hidden = false;
    banner.innerHTML =
      `<strong>Last successful run was ${Math.floor(ageDays)} days ago.</strong> ` +
      "The weekly run may not have completed — these numbers are the last good run, not today's.";
  }
}

function renderLegend() {
  document.getElementById("legend").hidden = false;
}

function renderCoverage(data) {
  const cov = data.coverage || {};
  const without = cov.rules_without_test || [];
  document.getElementById("coverage").hidden = false;
  const n = without.length;
  const total = cov.rules_in_pack ?? "?";
  document.getElementById("coverage-text").textContent =
    n === 0
      ? `Every rule in the pack has an Atomic Red Team test.`
      : `${n} of ${total} rules do not yet have an Atomic Red Team test. ` +
        `We commit to adding coverage on a weekly cadence; naming the gap beats hiding it.`;
  document.getElementById("coverage-list").textContent = n ? "Untested: " + without.join(", ") : "";
}

function wireControls() {
  document.getElementById("table-section").hidden = false;

  document.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (STATE.sortKey === key) STATE.sortDir *= -1;
      else { STATE.sortKey = key; STATE.sortDir = 1; }
      renderTable();
    });
  });

  const filter = document.getElementById("filter");
  filter.addEventListener("input", () => {
    STATE.filter = filter.value.trim().toLowerCase();
    renderTable();
  });

  const onlyCovered = document.getElementById("only-covered");
  onlyCovered.addEventListener("change", () => {
    STATE.onlyCovered = onlyCovered.checked;
    renderTable();
  });
}

function renderTable() {
  const body = document.getElementById("rules-body");
  body.innerHTML = "";

  let rows = STATE.rules.slice();
  if (STATE.onlyCovered) rows = rows.filter((r) => r.has_test);
  if (STATE.filter) {
    rows = rows.filter((r) =>
      [r.id, r.name, r.mitre?.technique_id, r.mitre?.technique_name]
        .filter(Boolean)
        .some((v) => v.toLowerCase().includes(STATE.filter))
    );
  }
  rows.sort(makeComparator(STATE.sortKey, STATE.sortDir));
  updateSortIndicators();

  const frag = document.createDocumentFragment();
  for (const r of rows) frag.appendChild(rowEl(r));
  body.appendChild(frag);
}

function rowEl(r) {
  const tr = document.createElement("tr");
  const mitreId = r.mitre?.technique_id || "—";
  const cat = r.latest_category;
  tr.innerHTML =
    `<td class="rule-id">${escapeHtml(r.id)}</td>` +
    `<td class="rule-name">${escapeHtml(r.name || "")}</td>` +
    `<td class="mitre">${escapeHtml(mitreId)}</td>` +
    `<td>${sparkline(r.history)}</td>` +
    `<td>${pill(cat)}</td>` +
    `<td class="reason">${escapeHtml(r.latest_reason || "")}</td>`;
  return tr;
}

function sparkline(history) {
  if (!history || !history.length) return '<span class="muted">—</span>';
  const dots = history
    .map((h) => {
      const c = h.category || "none";
      const title = `${h.iso_week}: ${CATEGORY_LABEL[h.category] || "no test"}`;
      return `<span class="dot dot-${c}" title="${escapeHtml(title)}"></span>`;
    })
    .join("");
  return `<span class="spark">${dots}</span>`;
}

function pill(cat) {
  const cls = cat || "none";
  const label = cat ? CATEGORY_LABEL[cat] || cat : "Untested";
  return `<span class="pill pill-${cls}">${escapeHtml(label)}</span>`;
}

function makeComparator(key, dir) {
  return (a, b) => {
    let av, bv;
    if (key === "mitre") { av = a.mitre?.technique_id || ""; bv = b.mitre?.technique_id || ""; }
    else if (key === "latest_category") {
      av = CATEGORY_ORDER[a.latest_category] ?? 99;
      bv = CATEGORY_ORDER[b.latest_category] ?? 99;
      return (av - bv) * dir;
    } else { av = a[key] || ""; bv = b[key] || ""; }
    return String(av).localeCompare(String(bv), undefined, { numeric: true }) * dir;
  };
}

function updateSortIndicators() {
  document.querySelectorAll("th.sortable").forEach((th) => {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.sort === STATE.sortKey) {
      th.classList.add(STATE.sortDir === 1 ? "sorted-asc" : "sorted-desc");
    }
  });
}

/* ---- helpers ---- */
function sep() { return '<span class="sep">·</span>'; }

function formatDate(iso) {
  if (!iso) return "unknown";
  const d = new Date(iso);
  if (isNaN(d)) return "unknown";
  return d.toLocaleString("en-IE", {
    weekday: "short", year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short",
  });
}

function daysSince(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (isNaN(d)) return null;
  return (Date.now() - d.getTime()) / 86400000;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
