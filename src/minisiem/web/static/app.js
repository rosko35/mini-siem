/* mini-siem dashboard.
 *
 * Everything shown here (usernames, paths, user agents) is attacker-controlled
 * text from log files, so DOM nodes are always built with textContent and
 * never with innerHTML.
 */
"use strict";

const REFRESH_MS = 30_000;
const regionNames = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;
const charts = {};
let map = null;

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const fmt = new Intl.NumberFormat("en");

function countryName(code) {
  if (!code || code === "??") return "Unknown";
  try { return regionNames ? regionNames.of(code) : code; } catch { return code; }
}

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

function link(href, text) {
  const a = el("a", text);
  a.href = href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}

function fillTable(tbodyId, rows, makeCells, emptyText = "No data yet") {
  const tbody = document.getElementById(tbodyId);
  tbody.replaceChildren();
  if (!rows.length) {
    const tr = el("tr");
    const td = el("td", emptyText, "muted");
    td.colSpan = 99;
    tr.append(td);
    tbody.append(tr);
    return;
  }
  for (const row of rows) {
    const tr = el("tr");
    for (const cell of makeCells(row)) {
      tr.append(cell instanceof Node ? cell : el("td", cell));
    }
    tbody.append(tr);
  }
}

function td(content, cls) {
  const cell = el("td", null, cls);
  if (content instanceof Node) cell.append(content); else cell.textContent = content ?? "";
  return cell;
}

function shortTime(iso) {
  return iso ? iso.replace("T", " ").replace("+00:00", "").slice(0, 16) : "";
}

async function api(path) {
  const res = await fetch(path, { credentials: "same-origin", cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json();
}

function upsertChart(id, config) {
  if (charts[id]) {
    charts[id].data = config.data;
    charts[id].update();
    return;
  }
  charts[id] = new Chart(document.getElementById(id), config);
}

function baseOptions(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: { legend: { labels: { color: css("--text") } } },
    scales: {
      x: { ticks: { color: css("--muted") }, grid: { color: css("--grid") } },
      y: { ticks: { color: css("--muted") }, grid: { color: css("--grid") }, beginAtZero: true },
    },
    ...extra,
  };
}

function renderSummary(s) {
  document.getElementById("kpi-ssh").textContent = fmt.format(s.ssh_attempts);
  document.getElementById("kpi-http").textContent = fmt.format(s.http_suspicious);
  document.getElementById("kpi-ips").textContent = fmt.format(s.attacker_ips);
  document.getElementById("kpi-users").textContent = fmt.format(s.usernames);
  document.getElementById("kpi-alerts").textContent = fmt.format(s.alerts);
}

function renderMap(countries) {
  const values = {};
  let unknown = 0;
  for (const c of countries) {
    if (c.country === "??") unknown += c.count; else values[c.country] = c.count;
  }
  const note = document.getElementById("map-note");
  note.textContent = unknown
    ? `${fmt.format(unknown)} events from addresses without a known country (no GeoIP database, or private ranges).`
    : "";
  if (typeof jsVectorMap === "undefined") {
    document.getElementById("map").textContent = "Map library could not be loaded.";
    return;
  }
  const container = document.getElementById("map");
  if (map) { try { map.destroy(); } catch { /* ignore */ } }
  container.replaceChildren();
  const hasData = Object.keys(values).length > 0;
  map = new jsVectorMap({
    selector: "#map",
    map: "world",
    zoomButtons: true,
    regionStyle: { initial: { fill: css("--map-empty"), stroke: css("--bg"), strokeWidth: 0.4 } },
    visualizeData: hasData ? { scale: [css("--map-low"), css("--map-high")], values } : undefined,
    onRegionTooltipShow(event, tooltip, code) {
      const n = values[code] || 0;
      tooltip.text(`${countryName(code)}: ${fmt.format(n)} events`);
    },
  });
}

function renderHourly(rows) {
  upsertChart("hourly", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.hour.slice(5, 13).replace("T", " ") + "h"),
      datasets: [
        { label: "SSH attempts", data: rows.map((r) => r.ssh_attempts), backgroundColor: css("--c1"), stack: "s" },
        { label: "Suspicious HTTP", data: rows.map((r) => r.http_suspicious), backgroundColor: css("--c2"), stack: "s" },
        { label: "Alerts", data: rows.map((r) => r.alerts), type: "line", borderColor: css("--c3"),
          backgroundColor: css("--c3"), pointRadius: 0, tension: 0.25, yAxisID: "y1" },
      ],
    },
    options: baseOptions({
      scales: {
        x: { stacked: true, ticks: { color: css("--muted"), maxTicksLimit: 12 }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: css("--muted") }, grid: { color: css("--grid") } },
        y1: { position: "right", beginAtZero: true, ticks: { color: css("--c3") }, grid: { display: false } },
      },
    }),
  });
}

function renderTopIps(rows) {
  fillTable("top-ips", rows, (r) => [
    td(r.ip, "mono"),
    td(countryName(r.country)),
    td(fmt.format(r.ssh), "num"),
    td(fmt.format(r.http), "num"),
    td(shortTime(r.last_seen), "muted"),
  ]);
}

function renderUsernames(rows) {
  upsertChart("usernames", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.user),
      datasets: [{ label: "Attempts", data: rows.map((r) => r.count), backgroundColor: css("--c1") }],
    },
    options: baseOptions({ indexAxis: "y", plugins: { legend: { display: false } } }),
  });
}

function renderByRule(rows) {
  upsertChart("by-rule", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.rule_name),
      datasets: [{
        label: "Alerts",
        data: rows.map((r) => r.count),
        backgroundColor: rows.map((r) => css(`--sev${r.severity}`)),
      }],
    },
    options: baseOptions({ indexAxis: "y", plugins: { legend: { display: false } } }),
  });
}

function renderMitre(rows) {
  fillTable("mitre", rows, (r) => {
    const cell = el("td");
    cell.append(link(r.url, r.id), el("span", r.name ? ` ${r.name}` : ""));
    return [cell, td(r.tactic, "muted"), td(r.rules.join(", "), "small"), td(fmt.format(r.alerts), "num")];
  });
}

const SEVERITY = { 1: "low", 2: "medium", 3: "high", 4: "critical" };

function renderAlerts(rows) {
  fillTable("alerts", rows, (r) => {
    const sev = el("span", SEVERITY[r.severity] || r.severity, `badge sev${r.severity}`);
    const source = el("td");
    source.append(el("span", r.key, "mono"));
    if (r.country) source.append(el("span", ` ${r.country}`, "muted"));
    const mitre = el("td");
    r.mitre.forEach((t, i) => {
      if (i) mitre.append(" ");
      const a = link(t.url, t.id);
      a.title = t.name;
      mitre.append(a);
    });
    const msg = td(r.message, "message");
    msg.title = r.sample || "";
    return [td(shortTime(r.ts), "muted nowrap"), td(sev), td(r.rule_id, "mono small"), source, msg, mitre];
  }, "No alerts - quiet day.");
}

async function refresh() {
  const days = document.getElementById("days").value;
  const hours = Math.min(days * 24, 24 * 31);
  document.getElementById("range-label").textContent = `last ${days === "1" ? "24 hours" : days + " days"}`;
  try {
    const [summary, countries, hourly, ips, users, byRule, mitre, alerts] = await Promise.all([
      api(`/api/summary?days=${days}`),
      api(`/api/countries?days=${days}`),
      api(`/api/hourly?hours=${hours}`),
      api(`/api/top-ips?days=${days}&limit=10`),
      api(`/api/top-usernames?days=${days}&limit=10`),
      api(`/api/alerts/by-rule?days=${days}`),
      api(`/api/mitre?days=${days}`),
      api("/api/alerts/recent?limit=50"),
    ]);
    renderSummary(summary);
    renderMap(countries);
    renderHourly(hourly);
    renderTopIps(ips);
    renderUsernames(users);
    renderByRule(byRule);
    renderMitre(mitre);
    renderAlerts(alerts);
    document.getElementById("updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    document.getElementById("updated").textContent = `error: ${err.message}`;
  }
}

document.getElementById("days").addEventListener("change", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
