"use strict";

/* Compact Checkout savings dashboard.
   Data: window.DASHBOARD_DATA (dashboard-data.js), falling back to
   dashboard-data.json when served over HTTP. All figures measured by
   dashboard_data.py with tiktoken o200k_base. */

function fmtInt(v) {
  return typeof v === "number" ? v.toLocaleString("en-US") : "—";
}

function fmtRatio(v) {
  return typeof v === "number" ? v.toFixed(2) + "×" : "—";
}

var VERDICTS = {
  approved: { label: "Approved", cls: "pass" },
  blocked: { label: "Blocked", cls: "fail" },
  needs_confirmation: { label: "Needs confirmation", cls: "fail" }
};

function verdictCell(params) {
  var v = VERDICTS[params.value] || { label: String(params.value), cls: "fail" };
  var span = document.createElement("span");
  span.className = "chip " + v.cls;
  span.textContent = v.label;
  return span;
}

var NUM_COL = { type: "numericColumn", width: 104 };

var SCENARIO_COLS = [
  { field: "scenario", headerName: "Scenario", flex: 1, minWidth: 210 },
  { field: "items", headerName: "Items", width: 76, type: "numericColumn", filter: false },
  { field: "amount", headerName: "Amount", width: 92, filter: false },
  { field: "verdict", headerName: "Verdict", width: 158, cellRenderer: verdictCell },
  Object.assign({ field: "prose_tokens", headerName: "Prose", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  Object.assign({ field: "packet_tokens", headerName: "Packet", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  Object.assign({ field: "tokens_saved", headerName: "Saved", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  { field: "ratio", headerName: "Ratio", width: 88, type: "numericColumn", valueFormatter: function (p) { return fmtRatio(p.value); } },
  { field: "checksum", headerName: "Checksum", width: 108, cellClass: "mono", filter: false }
];

var SWEEP_COLS = [
  { field: "items", headerName: "Items", width: 84, type: "numericColumn", filter: false },
  { field: "amount", headerName: "Amount", flex: 1, minWidth: 92, filter: false },
  { field: "verdict", headerName: "Verdict", width: 158, cellRenderer: verdictCell },
  Object.assign({ field: "prose_tokens", headerName: "Prose", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  Object.assign({ field: "packet_tokens", headerName: "Packet", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  Object.assign({ field: "tokens_saved", headerName: "Saved", valueFormatter: function (p) { return fmtInt(p.value); } }, NUM_COL),
  { field: "ratio", headerName: "Ratio", width: 88, type: "numericColumn", valueFormatter: function (p) { return fmtRatio(p.value); } }
];

function makeGrid(elId, emptyId, cols, rows) {
  var el = document.getElementById(elId);
  if (!rows || !rows.length) {
    el.hidden = true;
    document.getElementById(emptyId).hidden = false;
    return;
  }
  agGrid.createGrid(el, {
    columnDefs: cols,
    rowData: rows,
    defaultColDef: { sortable: true, filter: true, resizable: true, suppressMovable: true },
    animateRows: false,
    domLayout: "normal"
  });
}

function fillStats(data) {
  var s = data.summary;
  var big = data.sweep[data.sweep.length - 1];
  document.getElementById("statRatio").textContent = fmtRatio(s.flagship_ratio);
  document.getElementById("statRatioSub").textContent =
    s.flagship_scenario + " · " + fmtInt(s.flagship_prose_tokens) + " → " + fmtInt(s.flagship_packet_tokens) + " tokens";
  document.getElementById("statSaved").textContent = fmtInt(s.total_tokens_saved);
  document.getElementById("statSavedSub").textContent =
    fmtInt(s.total_prose_tokens) + " prose → " + fmtInt(s.total_packet_tokens) + " packet";
  document.getElementById("statSweep").textContent = fmtRatio(s.best_sweep_ratio);
  document.getElementById("statSweepSub").textContent = s.best_sweep_items + " line items";
  document.getElementById("statSweepSaved").textContent = fmtInt(big.tokens_saved);
  document.getElementById("statSweepSavedSub").textContent =
    fmtInt(big.prose_tokens) + " prose → " + fmtInt(big.packet_tokens) + " packet";
}

function init(data) {
  fillStats(data);
  makeGrid("scenarioGrid", "scenarioEmpty", SCENARIO_COLS, data.scenarios);
  makeGrid("sweepGrid", "sweepEmpty", SWEEP_COLS, data.sweep);
}

if (window.DASHBOARD_DATA) {
  init(window.DASHBOARD_DATA);
} else {
  fetch("dashboard-data.json")
    .then(function (r) { return r.json(); })
    .then(init)
    .catch(function () {
      document.getElementById("scenarioGrid").hidden = true;
      document.getElementById("sweepGrid").hidden = true;
      document.getElementById("scenarioEmpty").hidden = false;
      document.getElementById("sweepEmpty").hidden = false;
    });
}
