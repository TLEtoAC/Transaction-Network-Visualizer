#!/usr/bin/env python3
"""
Transaction Network Analyzer
=============================
Handles CSVs with millions of rows via chunked streaming.
Builds a NetworkX graph, computes graph metrics, detects suspicious
communities, then exports an interactive Pyvis HTML dashboard.

Usage:
    python analyze.py transactions.csv [options]

Options:
    --sender       COL   Column name for sender   (default: auto-detect)
    --receiver     COL   Column name for receiver (default: auto-detect)
    --amount       COL   Column name for amount   (default: auto-detect)
    --timestamp    COL   Column name for timestamp (optional)
    --suspicious   COL   Column name for suspicious flag (optional)
    --susp-pct     N     Auto-flag top N% of transactions by amount (default: 10)
    --sample       N     Max edges to render in graph (default: 50000)
    --output       FILE  Output HTML file (default: network_report.html)
    --chunk-size   N     CSV rows per chunk (default: 100000)
"""

import argparse
import sys
import os
import time
import json
import math
from pathlib import Path
from collections import defaultdict

import pandas as pd
import networkx as nx

# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Transaction Network Analyzer")
    p.add_argument("csv_file", help="Path to CSV file")
    p.add_argument("--sender",     default=None)
    p.add_argument("--receiver",   default=None)
    p.add_argument("--amount",     default=None)
    p.add_argument("--timestamp",  default=None)
    p.add_argument("--suspicious", default=None)
    p.add_argument("--susp-pct",   type=float, default=10,
                   help="Flag top N%% transactions by amount as suspicious (default 10)")
    p.add_argument("--sample",     type=int,   default=50_000,
                   help="Max edges rendered in graph (default 50000)")
    p.add_argument("--output",     default="network_report.html")
    p.add_argument("--chunk-size", type=int,   default=100_000)
    return p.parse_args()

# ─────────────────────────────────────────────────────────────
#  COLUMN AUTO-DETECTION
# ─────────────────────────────────────────────────────────────
ALIASES = {
    "sender":    ["sender","from","source","payer","originator","account_from","from_account","from_id","sender_id","debit_account"],
    "receiver":  ["receiver","to","destination","payee","beneficiary","counterparty","account_to","to_account","to_id","receiver_id","credit_account","recipient"],
    "amount":    ["amount","value","sum","total","txn_amount","transaction_amount","amt","price","payment_amount"],
    "timestamp": ["timestamp","date","time","datetime","txn_date","transaction_date","created_at","date_time","trans_date","value_date"],
    "suspicious":["suspicious","is_suspicious","flagged","flag","fraud","is_fraud","alert","anomaly","risk_flag"],
}

def detect_col(headers, role, explicit=None):
    """Return best matching column name or None."""
    lh = {h.lower().strip(): h for h in headers}
    if explicit:
        if explicit in headers:
            return explicit
        if explicit.lower() in lh:
            return lh[explicit.lower()]
        print(f"  ⚠  Column '{explicit}' not found. Falling back to auto-detect.")
    for alias in ALIASES[role]:
        if alias in lh:
            return lh[alias]
    return None

def require_col(headers, role, explicit=None, csv_file=None):
    col = detect_col(headers, role, explicit)
    if col is None:
        print(f"\n✗  Cannot find '{role}' column.")
        print(f"   Detected columns: {headers}")
        print(f"   Pass --{role} COLNAME to specify it explicitly.")
        sys.exit(1)
    return col

# ─────────────────────────────────────────────────────────────
#  STREAMING CSV AGGREGATOR
# ─────────────────────────────────────────────────────────────
class StreamAggregator:
    """
    Streams the CSV in chunks. For each chunk it accumulates:
      - edge_stats[from][to] = {total_amount, count, susp_count, min_ts, max_ts}
      - node_vol[node]       = {inflow, outflow, txn_count}
      - global stats
    Memory stays O(unique_edges), not O(rows).
    """
    def __init__(self, col_from, col_to, col_amount, col_ts, col_susp, susp_pct, chunk_size):
        self.col_from   = col_from
        self.col_to     = col_to
        self.col_amount = col_amount
        self.col_ts     = col_ts
        self.col_susp   = col_susp
        self.susp_pct   = susp_pct
        self.chunk_size = chunk_size

        self.edge_stats  = defaultdict(lambda: defaultdict(lambda: {
            "total": 0.0, "count": 0, "susp": 0, "min_ts": None, "max_ts": None
        }))
        self.node_vol    = defaultdict(lambda: {"inflow":0.0,"outflow":0.0,"txn_count":0,"susp_count":0})
        self.total_rows  = 0
        self.bad_rows    = 0
        self.total_amount= 0.0
        self.amounts_sample = []   # reservoir sample for percentile calc
        self.has_susp_col= False
        self.ts_min      = None
        self.ts_max      = None

    def ingest(self, path):
        t0 = time.time()
        chunk_n = 0
        use_cols = [self.col_from, self.col_to, self.col_amount]
        if self.col_ts:   use_cols.append(self.col_ts)
        if self.col_susp: use_cols.append(self.col_susp)

        reader = pd.read_csv(
            path,
            usecols=use_cols,
            chunksize=self.chunk_size,
            low_memory=False,
            on_bad_lines="skip",
        )

        print(f"\n  Streaming CSV in chunks of {self.chunk_size:,} rows…")
        for chunk in reader:
            chunk_n += 1
            self._process_chunk(chunk)
            elapsed = time.time() - t0
            rate = self.total_rows / elapsed if elapsed > 0 else 0
            print(f"  chunk {chunk_n:4d} | {self.total_rows:>12,} rows | "
                  f"{rate:>10,.0f} rows/s | "
                  f"{len(self.edge_stats):>8,} unique edges", end="\r")

        print()  # newline after \r
        print(f"  ✓  {self.total_rows:,} rows processed in {time.time()-t0:.1f}s "
              f"({self.bad_rows:,} skipped).")

        # If no explicit suspicious column → flag by percentile
        if not self.has_susp_col and self.amounts_sample:
            threshold = _percentile(self.amounts_sample, 100 - self.susp_pct)
            print(f"  Auto-flagging transactions ≥ ${threshold:,.2f} "
                  f"(top {self.susp_pct:.0f}% by amount).")
            for frm, tos in self.edge_stats.items():
                for to, s in tos.items():
                    # We only have aggregated total; re-flag based on avg heuristic
                    avg = s["total"] / s["count"] if s["count"] else 0
                    if avg >= threshold:
                        s["susp"] = s["count"]

    def _process_chunk(self, chunk):
        cf, ct, ca = self.col_from, self.col_to, self.col_amount

        # Drop rows missing required fields
        chunk = chunk.dropna(subset=[cf, ct, ca])
        chunk[ca] = pd.to_numeric(
            chunk[ca].astype(str).str.replace(r"[$,\s]", "", regex=True),
            errors="coerce"
        )
        chunk = chunk[chunk[ca] > 0].dropna(subset=[ca])

        self.total_rows  += len(chunk)
        self.bad_rows    += (len(chunk) - len(chunk))  # already filtered

        # Reservoir sample of amounts (up to 500k) for percentile
        if len(self.amounts_sample) < 500_000:
            self.amounts_sample.extend(chunk[ca].tolist())

        # Timestamps
        if self.col_ts and self.col_ts in chunk.columns:
            ts_series = pd.to_datetime(chunk[self.col_ts], errors="coerce").dropna()
            if not ts_series.empty:
                mn, mx = ts_series.min(), ts_series.max()
                self.ts_min = mn if self.ts_min is None else min(self.ts_min, mn)
                self.ts_max = mx if self.ts_max is None else max(self.ts_max, mx)

        # Suspicious flag
        susp_flags = None
        if self.col_susp and self.col_susp in chunk.columns:
            self.has_susp_col = True
            susp_flags = chunk[self.col_susp].astype(str).str.strip().str.lower().isin(
                ["true","1","yes","y","flagged","fraud","suspicious"]
            )

        # Aggregate edges
        for i, row in enumerate(chunk.itertuples(index=False)):
            frm    = str(getattr(row, _safe(cf)))
            to     = str(getattr(row, _safe(ct)))
            amount = float(getattr(row, _safe(ca)))
            is_susp = bool(susp_flags.iloc[i]) if susp_flags is not None else False

            s = self.edge_stats[frm][to]
            s["total"] += amount
            s["count"] += 1
            if is_susp: s["susp"] += 1

            if self.col_ts and self.col_ts in chunk.columns:
                raw_ts = chunk[self.col_ts].iloc[i]
                # skip per-row ts parsing for speed on huge files

            nf = self.node_vol[frm]
            nf["outflow"]   += amount
            nf["txn_count"] += 1
            if is_susp: nf["susp_count"] += 1

            nt = self.node_vol[to]
            nt["inflow"]    += amount
            nt["txn_count"] += 1
            if is_susp: nt["susp_count"] += 1

            self.total_amount += amount

def _safe(col): return col.replace(" ","_").replace("-","_").replace(".","_")

def _percentile(data, pct):
    s = sorted(data)
    k = (len(s)-1) * pct / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f==c else s[f]*(c-k)+s[c]*(k-f)

# ─────────────────────────────────────────────────────────────
#  BUILD NETWORKX GRAPH
# ─────────────────────────────────────────────────────────────
def build_graph(agg, sample_limit):
    """
    Builds a weighted directed graph from the aggregated edge stats.
    If unique edges > sample_limit, keeps the top edges by total amount.
    """
    edge_items = [
        (frm, to, stats)
        for frm, tos in agg.edge_stats.items()
        for to, stats in tos.items()
    ]

    total_edges = len(edge_items)
    print(f"\n  Building graph: {total_edges:,} unique edges, "
          f"{len(agg.node_vol):,} unique nodes.")

    if total_edges > sample_limit:
        print(f"  ⚠  Graph too large to render fully. "
              f"Sampling top {sample_limit:,} edges by total amount.")
        edge_items.sort(key=lambda x: x[2]["total"], reverse=True)
        edge_items = edge_items[:sample_limit]

    G = nx.DiGraph()

    for frm, to, s in edge_items:
        G.add_edge(
            frm, to,
            weight     = s["total"],
            count      = s["count"],
            susp_count = s["susp"],
            suspicious = s["susp"] > 0,
            avg_amount = s["total"] / s["count"] if s["count"] else 0,
        )

    # Attach node metrics
    for node in G.nodes():
        nv = agg.node_vol.get(node, {})
        G.nodes[node]["inflow"]     = nv.get("inflow", 0)
        G.nodes[node]["outflow"]    = nv.get("outflow", 0)
        G.nodes[node]["txn_count"]  = nv.get("txn_count", 0)
        G.nodes[node]["susp_count"] = nv.get("susp_count", 0)
        G.nodes[node]["net_flow"]   = nv.get("inflow",0) - nv.get("outflow",0)

    return G, total_edges

# ─────────────────────────────────────────────────────────────
#  GRAPH ANALYTICS
# ─────────────────────────────────────────────────────────────
def compute_analytics(G, agg):
    print("\n  Computing graph analytics…")
    stats = {}

    # Degree centrality
    in_deg  = dict(G.in_degree(weight="weight"))
    out_deg = dict(G.out_degree(weight="weight"))
    for n in G.nodes():
        G.nodes[n]["weighted_in_degree"]  = in_deg.get(n, 0)
        G.nodes[n]["weighted_out_degree"] = out_deg.get(n, 0)

    # PageRank (funds-flow importance)
    try:
        pr = nx.pagerank(G, weight="weight", max_iter=200)
        for n, v in pr.items(): G.nodes[n]["pagerank"] = round(v, 6)
        stats["pagerank_ok"] = True
    except Exception as e:
        print(f"    PageRank skipped: {e}")
        stats["pagerank_ok"] = False

    # Strongly connected components (circular flow / cycles)
    sccs = sorted(nx.strongly_connected_components(G), key=len, reverse=True)
    scc_map = {}
    for i, scc in enumerate(sccs):
        for n in scc: scc_map[n] = i
    for n in G.nodes(): G.nodes[n]["scc_id"] = scc_map.get(n, -1)

    large_sccs = [s for s in sccs if len(s) >= 3]
    # Only treat SCCs as "circular flow" if they are small relative to the graph.
    # A giant SCC just means a dense connected graph — not a laundering ring.
    total_nodes = G.number_of_nodes()
    meaningful_sccs = [s for s in large_sccs if 2 < len(s) <= max(6, total_nodes * 0.01)]
    stats["n_cycles"]      = len(meaningful_sccs)
    stats["largest_cycle"] = len(meaningful_sccs[0]) if meaningful_sccs else 0
    print(f"    Meaningful circular flows detected: {len(meaningful_sccs)}")
    cycle_nodes = set()
    for scc in meaningful_sccs: cycle_nodes.update(scc)
    for n in G.nodes():
        G.nodes[n]["in_cycle"] = n in cycle_nodes

    # Suspicious node: use edge-level susp flags from the graph, not the raw aggregator
    # (aggregator susp_count can be inflated if auto-flag touched many edges)
    susp_nodes = set()
    for n in G.nodes():
        nd = G.nodes[n]
        # Count suspicious edges touching this node directly from graph
        out_susp = sum(1 for nb in G.successors(n)   if G[n][nb].get("suspicious", False))
        in_susp  = sum(1 for nb in G.predecessors(n) if G[nb][n].get("suspicious", False))
        out_total= G.out_degree(n)
        in_total = G.in_degree(n)
        total_deg = (out_total + in_total) or 1
        susp_deg  = out_susp + in_susp
        susp_ratio = susp_deg / total_deg

        is_susp = susp_ratio > 0.25 or (nd.get("in_cycle") and susp_deg > 0)
        if is_susp:
            susp_nodes.add(n)
        nd["suspicious"] = is_susp
        nd["susp_edge_count"] = susp_deg

    stats["susp_nodes"]    = len(susp_nodes)
    stats["cycle_nodes"]   = len(cycle_nodes)
    stats["total_nodes"]   = G.number_of_nodes()
    stats["total_edges"]   = G.number_of_edges()
    stats["total_amount"]  = agg.total_amount
    stats["total_rows"]    = agg.total_rows
    stats["ts_min"]        = str(agg.ts_min)[:10] if agg.ts_min else None
    stats["ts_max"]        = str(agg.ts_max)[:10] if agg.ts_max else None

    print(f"    Suspicious nodes: {len(susp_nodes)}")
    print(f"    Nodes in cycles:  {len(cycle_nodes)}")

    return stats

# ─────────────────────────────────────────────────────────────
#  TOP-N TABLE DATA
# ─────────────────────────────────────────────────────────────
def top_nodes(G, n=20):
    rows = []
    for node in G.nodes():
        nd = G.nodes[node]
        rows.append({
            "id":         node,
            "inflow":     nd.get("inflow", 0),
            "outflow":    nd.get("outflow", 0),
            "txn_count":  nd.get("txn_count", 0),
            "susp_count": nd.get("susp_count", 0),
            "pagerank":   nd.get("pagerank", 0),
            "in_cycle":   nd.get("in_cycle", False),
            "suspicious": nd.get("suspicious", False),
        })
    rows.sort(key=lambda r: r["inflow"]+r["outflow"], reverse=True)
    return rows[:n]

# ─────────────────────────────────────────────────────────────
#  HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────────
def build_html(G, stats, top, output_path, csv_name, sampled, total_edges):
    """Generates a self-contained interactive HTML report using vis.js."""

    # Prepare node/edge data for vis.js
    nodes_js, edges_js = [], []

    max_inflow = max((G.nodes[n].get("inflow",1) for n in G.nodes()), default=1)

    for node in G.nodes():
        nd   = G.nodes[node]
        inf  = nd.get("inflow", 0)
        outf = nd.get("outflow", 0)
        tc   = nd.get("txn_count", 0)
        susp = nd.get("suspicious", False)
        cyc  = nd.get("in_cycle", False)
        pr   = nd.get("pagerank", 0)
        sc   = nd.get("susp_count", 0)
        net  = nd.get("net_flow", 0)

        size  = 12 + 28 * (inf / max_inflow) ** 0.4 if max_inflow > 0 else 16
        color = "#E24B4A" if susp else ("#F4A823" if cyc else "#378ADD")
        border= "#A32D2D" if susp else ("#C07810" if cyc else "#185FA5")

        label = node if len(node) <= 18 else node[:17] + "…"
        tooltip = (
            f"<b>{node}</b><br>"
            f"Inflow: {fmt_amt(inf)}<br>"
            f"Outflow: {fmt_amt(outf)}<br>"
            f"Net: {fmt_amt(net)}<br>"
            f"Transactions: {tc:,}<br>"
            f"Suspicious txns: {sc:,}<br>"
            f"PageRank: {pr:.5f}<br>"
            f"{'⚠ In circular flow<br>' if cyc else ''}"
            f"{'🚨 Flagged suspicious' if susp else ''}"
        )

        nodes_js.append({
            "id":          node,
            "label":       label,
            "title":       tooltip,
            "size":        round(size, 1),
            "color":       {"background": color, "border": border,
                            "highlight": {"background": color, "border": "#fff"}},
            "font":        {"size": 11, "color": "#333"},
            "borderWidth": 2 if susp else 1,
            "_susp":       susp,
            "_cycle":      cyc,
            "_inflow":     inf,
            "_outflow":    outf,
            "_tc":         tc,
            "_sc":         sc,
            "_pr":         pr,
            "_net":        net,
        })

    max_weight = max((G.edges[e].get("weight",1) for e in G.edges()), default=1)
    for u, v, ed in G.edges(data=True):
        w     = ed.get("weight", 0)
        susp  = ed.get("suspicious", False)
        cnt   = ed.get("count", 1)
        avg   = ed.get("avg_amount", 0)
        width = 1 + 6 * (w / max_weight) ** 0.5

        edges_js.append({
            "from":   u,
            "to":     v,
            "title":  f"Total: {fmt_amt(w)}<br>Transactions: {cnt:,}<br>Avg: {fmt_amt(avg)}<br>{'🚨 Suspicious' if susp else 'Normal'}",
            "width":  round(width, 2),
            "color":  {"color": "#E24B4A" if susp else "#378ADD",
                       "opacity": 0.75,
                       "highlight": "#FF6B6B" if susp else "#5AA8FF"},
            "arrows": "to",
            "_susp":  susp,
            "_weight":w,
            "_count": cnt,
        })

    nodes_json = json.dumps(nodes_js, ensure_ascii=False)
    edges_json = json.dumps(edges_js, ensure_ascii=False)
    stats_json = json.dumps(stats, ensure_ascii=False)
    top_json   = json.dumps(top,   ensure_ascii=False)

    sampled_note = (
        f"<span style='color:#c0392b'>⚠ Showing top {len(edges_js):,} of "
        f"{total_edges:,} unique edges by volume</span>"
        if sampled else
        f"All {len(edges_js):,} unique edges rendered"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Transaction Network — {csv_name}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
<link  href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;height:100vh;display:flex;flex-direction:column;color:#1a1a1a}}
#topbar{{background:#fff;border-bottom:1px solid #e0e0e0;padding:0 16px;height:48px;display:flex;align-items:center;gap:12px;flex-shrink:0;flex-wrap:wrap}}
#topbar h1{{font-size:14px;font-weight:600}}
.badge{{font-size:11px;padding:2px 9px;border-radius:20px;background:#f0f0f0;color:#555;white-space:nowrap}}
.badge.susp{{background:#fce8e8;color:#c0392b}}
.badge.cycle{{background:#fff5e0;color:#b07800}}
.tb-sep{{width:1px;height:20px;background:#e8e8e8}}
.tb-btn{{font-size:12px;padding:4px 10px;border:1px solid #d8d8d8;border-radius:6px;background:#fff;color:#333;cursor:pointer;white-space:nowrap}}
.tb-btn:hover{{background:#f5f5f5}}
.tb-btn.active{{background:#e8f0fb;border-color:#a0b8e0;color:#1a5faa}}
#body{{display:flex;flex:1;overflow:hidden}}
#sidebar{{width:260px;flex-shrink:0;background:#fff;border-right:1px solid #e8e8e8;display:flex;flex-direction:column;overflow:hidden}}
#sidebar-tabs{{display:flex;border-bottom:1px solid #e8e8e8}}
.stab{{flex:1;padding:8px;font-size:12px;font-weight:500;text-align:center;cursor:pointer;color:#888;border-bottom:2px solid transparent}}
.stab.active{{color:#378ADD;border-color:#378ADD}}
#sidebar-content{{overflow-y:auto;flex:1;padding:12px;font-size:12px}}
.s-section{{margin-bottom:14px}}
.s-title{{font-size:10px;font-weight:700;color:#bbb;text-transform:uppercase;letter-spacing:.07em;margin-bottom:8px}}
.stat-row{{display:flex;justify-content:space-between;margin-bottom:4px}}
.stat-lbl{{color:#999}}
.stat-val{{font-weight:600;color:#1a1a1a}}
.legend-item{{display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:12px;color:#555}}
.leg-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}
.leg-line{{width:22px;height:2px;border-radius:1px;flex-shrink:0}}
#node-detail{{display:none}}
.nd-kv{{display:grid;grid-template-columns:1fr 1fr;gap:4px 12px;margin-bottom:8px}}
.nd-lbl{{color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:.04em}}
.nd-val{{font-weight:600;font-size:12px}}
#graph-wrap{{position:relative;flex:1;overflow:hidden;background:#fff}}
#graph{{width:100%;height:100%}}
#search-bar{{position:absolute;top:10px;right:10px;display:flex;gap:6px;z-index:5}}
#search-bar input{{font-size:12px;padding:5px 10px;border:1px solid #d8d8d8;border-radius:6px;width:180px;outline:none}}
#search-bar input:focus{{border-color:#378ADD}}
#search-bar button{{font-size:12px;padding:5px 10px;border:1px solid #d8d8d8;border-radius:6px;background:#fff;cursor:pointer}}
#search-bar button:hover{{background:#f0f0f0}}
#graph-controls{{position:absolute;bottom:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:5}}
.gc-btn{{width:30px;height:30px;border:1px solid #d8d8d8;border-radius:6px;background:#fff;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center}}
.gc-btn:hover{{background:#f0f0f0}}
#sampled-note{{position:absolute;bottom:12px;left:12px;font-size:11px;background:rgba(255,255,255,.9);padding:4px 10px;border-radius:6px;border:1px solid #e8e8e8}}
#top-table{{width:100%;border-collapse:collapse;font-size:11px}}
#top-table th{{text-align:left;padding:5px 6px;color:#aaa;font-weight:600;text-transform:uppercase;font-size:10px;border-bottom:1px solid #f0f0f0;white-space:nowrap}}
#top-table td{{padding:5px 6px;border-bottom:1px solid #f8f8f8;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
#top-table tr:hover td{{background:#f8faff}}
.susp-flag{{color:#c0392b;font-weight:700}}
.cycle-flag{{color:#b07800;font-weight:700}}
</style>
</head>
<body>

<div id="topbar">
  <h1>Transaction Network</h1>
  <span class="badge" id="file-badge">{csv_name}</span>
  <div class="tb-sep"></div>
  <button class="tb-btn active" id="btn-all"  onclick="filterView('all')">All</button>
  <button class="tb-btn"        id="btn-susp" onclick="filterView('suspicious')">Suspicious</button>
  <button class="tb-btn"        id="btn-cycle" onclick="filterView('cycle')">Circular flows</button>
  <div class="tb-sep"></div>
  <button class="tb-btn" onclick="network.fit()">Fit graph</button>
  <button class="tb-btn" onclick="togglePhysics()">Physics on/off</button>
</div>

<div id="body">
  <div id="sidebar">
    <div id="sidebar-tabs">
      <div class="stab active" onclick="showTab('stats')">Stats</div>
      <div class="stab"       onclick="showTab('detail')">Node detail</div>
      <div class="stab"       onclick="showTab('top')">Top accounts</div>
    </div>
    <div id="sidebar-content">

      <!-- STATS TAB -->
      <div id="tab-stats">
        <div class="s-section">
          <div class="s-title">Dataset</div>
          <div class="stat-row"><span class="stat-lbl">Source</span><span class="stat-val">{csv_name}</span></div>
          <div class="stat-row"><span class="stat-lbl">Total rows</span><span class="stat-val">{stats.get('total_rows',0):,}</span></div>
          {'<div class="stat-row"><span class="stat-lbl">Date range</span><span class="stat-val" style="font-size:11px">'+stats["ts_min"]+" – "+stats["ts_max"]+"</span></div>" if stats.get("ts_min") else ""}
          <div class="stat-row"><span class="stat-lbl">Total volume</span><span class="stat-val">{fmt_amt(stats.get("total_amount",0))}</span></div>
        </div>
        <div class="s-section">
          <div class="s-title">Graph (rendered)</div>
          <div class="stat-row"><span class="stat-lbl">Nodes</span><span class="stat-val">{stats.get("total_nodes",0):,}</span></div>
          <div class="stat-row"><span class="stat-lbl">Edges</span><span class="stat-val">{stats.get("total_edges",0):,}</span></div>
          <div class="stat-row"><span class="stat-lbl">Suspicious nodes</span><span class="stat-val" style="color:#c0392b">{stats.get("susp_nodes",0):,}</span></div>
          <div class="stat-row"><span class="stat-lbl">Circular flow nodes</span><span class="stat-val" style="color:#b07800">{stats.get("cycle_nodes",0):,}</span></div>
          <div class="stat-row"><span class="stat-lbl">Detected cycles</span><span class="stat-val">{stats.get("n_cycles",0):,}</span></div>
        </div>
        <div class="s-section">
          <div class="s-title">Legend — nodes</div>
          <div class="legend-item"><div class="leg-dot" style="background:#E24B4A"></div>Suspicious account</div>
          <div class="legend-item"><div class="leg-dot" style="background:#F4A823"></div>In circular flow</div>
          <div class="legend-item"><div class="leg-dot" style="background:#378ADD"></div>Normal account</div>
          <div style="font-size:10px;color:#ccc;margin-top:3px">Size = inflow volume</div>
        </div>
        <div class="s-section">
          <div class="s-title">Legend — edges</div>
          <div class="legend-item"><div class="leg-line" style="background:#E24B4A"></div>Suspicious txn</div>
          <div class="legend-item"><div class="leg-line" style="background:#378ADD"></div>Normal txn</div>
          <div style="font-size:10px;color:#ccc;margin-top:3px">Thickness = volume</div>
        </div>
      </div>

      <!-- DETAIL TAB -->
      <div id="tab-detail" style="display:none">
        <div id="node-detail">
          <div class="nd-kv" id="nd-kv"></div>
          <div class="s-title" style="margin-top:8px">Top connected accounts</div>
          <div id="nd-connections"></div>
        </div>
        <div id="node-placeholder" style="color:#bbb;font-size:12px;margin-top:20px;text-align:center">
          Click any node to see details
        </div>
      </div>

      <!-- TOP ACCOUNTS TAB -->
      <div id="tab-top" style="display:none">
        <div style="margin-bottom:8px;font-size:11px;color:#999">Top 20 accounts by total volume</div>
        <table id="top-table">
          <thead><tr>
            <th>Account</th><th>Inflow</th><th>Outflow</th><th>Txns</th><th>Flags</th>
          </tr></thead>
          <tbody id="top-tbody"></tbody>
        </table>
      </div>

    </div>
  </div>

  <div id="graph-wrap">
    <div id="graph"></div>
    <div id="search-bar">
      <input id="search-input" type="text" placeholder="Search account…" oninput="searchNode(this.value)">
      <button onclick="clearSearch()">✕</button>
    </div>
    <div id="graph-controls">
      <button class="gc-btn" onclick="network.fit()" title="Fit">⊡</button>
      <button class="gc-btn" onclick="zoomIn()"  title="Zoom in">+</button>
      <button class="gc-btn" onclick="zoomOut()" title="Zoom out">−</button>
    </div>
    <div id="sampled-note">{sampled_note}</div>
  </div>
</div>

<script>
const ALL_NODES = {nodes_json};
const ALL_EDGES = {edges_json};
const STATS     = {stats_json};
const TOP       = {top_json};

// ── Build vis.js datasets ──
const nodesDS = new vis.DataSet(ALL_NODES.map(n => ({{...n}})));
const edgesDS = new vis.DataSet(ALL_EDGES.map(e => ({{...e}})));

const container = document.getElementById('graph');
const network   = new vis.Network(container, {{nodes:nodesDS,edges:edgesDS}}, {{
  physics: {{
    enabled: true,
    stabilization: {{iterations:120, updateInterval:20}},
    barnesHut: {{gravitationalConstant:-8000, centralGravity:0.3, springLength:120, damping:0.12}},
  }},
  interaction: {{
    hover: true,
    tooltipDelay: 150,
    navigationButtons: false,
    zoomView: true,
  }},
  edges: {{
    smooth:{{type:'curvedCW',roundness:0.15}},
    arrows:{{to:{{enabled:true,scaleFactor:0.6}}}},
  }},
  nodes: {{
    shape:'dot',
    borderWidth:1,
    shadow:false,
  }},
}});

network.on('stabilizationProgress', p => {{
  const pct = Math.round(p.iterations/p.total*100);
  container.style.opacity = 0.4 + 0.6*(pct/100);
}});
network.on('stabilizationIterationsDone', () => {{
  container.style.opacity = 1;
  network.setOptions({{physics:{{enabled:false}}}});
  physicsOn = false;
}});

let physicsOn = true;
function togglePhysics(){{
  physicsOn = !physicsOn;
  network.setOptions({{physics:{{enabled:physicsOn}}}});
}}

// ── Filter view ──
let currentFilter = 'all';
function filterView(f){{
  currentFilter = f;
  ['btn-all','btn-susp','btn-cycle'].forEach(id=>document.getElementById(id).classList.remove('active'));
  document.getElementById('btn-'+f.replace('cycle','cycle')).classList.add('active');

  if(f==='all'){{
    nodesDS.update(ALL_NODES.map(n=>{{return {{id:n.id,hidden:false}};}}));
    edgesDS.update(ALL_EDGES.map(e=>{{return {{id:e.id,hidden:false}};}}));
  }} else if(f==='suspicious'){{
    nodesDS.update(ALL_NODES.map(n=>{{return {{id:n.id,hidden:!n._susp}};}}));
    edgesDS.update(ALL_EDGES.map(e=>{{return {{id:e.id,hidden:!e._susp}};}}));
  }} else if(f==='cycle'){{
    nodesDS.update(ALL_NODES.map(n=>{{return {{id:n.id,hidden:!n._cycle}};}}));
    edgesDS.update(ALL_EDGES.map(e=>{{
      const fn=ALL_NODES.find(x=>x.id===e.from),tn=ALL_NODES.find(x=>x.id===e.to);
      return {{id:e.id,hidden:!(fn&&fn._cycle&&tn&&tn._cycle)}};
    }}));
  }}
}}

// ── Node click → detail ──
network.on('click', params=>{{
  if(!params.nodes.length) return;
  const id  = params.nodes[0];
  const nd  = ALL_NODES.find(n=>n.id===id);
  if(!nd) return;
  showTab('detail');
  showNodeDetail(nd);
}});

function showNodeDetail(nd){{
  document.getElementById('node-placeholder').style.display='none';
  document.getElementById('node-detail').style.display='block';
  const kv = document.getElementById('nd-kv');
  kv.innerHTML = `
    <div><div class="nd-lbl">Account</div><div class="nd-val" style="word-break:break-all">${{nd.id}}</div></div>
    <div><div class="nd-lbl">Status</div><div class="nd-val" style="color:${{nd._susp?'#c0392b':nd._cycle?'#b07800':'#1e7e34'}}">${{nd._susp?'Suspicious':nd._cycle?'Circular flow':'Normal'}}</div></div>
    <div><div class="nd-lbl">Inflow</div><div class="nd-val" style="color:#1e7e34">${{fmtAmt(nd._inflow)}}</div></div>
    <div><div class="nd-lbl">Outflow</div><div class="nd-val" style="color:#c0392b">${{fmtAmt(nd._outflow)}}</div></div>
    <div><div class="nd-lbl">Net flow</div><div class="nd-val" style="color:${{nd._net>=0?'#1e7e34':'#c0392b'}}">${{fmtAmt(Math.abs(nd._net))}} ${{nd._net>=0?'surplus':'deficit'}}</div></div>
    <div><div class="nd-lbl">Transactions</div><div class="nd-val">${{nd._tc.toLocaleString()}}</div></div>
    <div><div class="nd-lbl">Suspicious txns</div><div class="nd-val" style="color:${{nd._sc>0?'#c0392b':'#aaa'}}">${{nd._sc.toLocaleString()}}</div></div>
    <div><div class="nd-lbl">PageRank</div><div class="nd-val">${{nd._pr.toFixed(5)}}</div></div>
  `;
  // Connections
  const connEl = document.getElementById('nd-connections');
  const outEdges = ALL_EDGES.filter(e=>e.from===nd.id).sort((a,b)=>b._weight-a._weight).slice(0,6);
  const inEdges  = ALL_EDGES.filter(e=>e.to===nd.id).sort((a,b)=>b._weight-a._weight).slice(0,6);
  connEl.innerHTML = `
    <div style="margin-top:6px;font-size:10px;color:#bbb;text-transform:uppercase;letter-spacing:.05em">Sends to</div>
    ${{outEdges.map(e=>`<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #f5f5f5;font-size:11px"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px;color:${{e._susp?'#c0392b':'#333'}}">${{e.to}}</span><span style="font-weight:600;flex-shrink:0">${{fmtAmt(e._weight)}}</span></div>`).join('')}}
    <div style="margin-top:8px;font-size:10px;color:#bbb;text-transform:uppercase;letter-spacing:.05em">Receives from</div>
    ${{inEdges.map(e=>`<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #f5f5f5;font-size:11px"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:130px;color:${{e._susp?'#c0392b':'#333'}}">${{e.from}}</span><span style="font-weight:600;flex-shrink:0">${{fmtAmt(e._weight)}}</span></div>`).join('')}}
  `;
}}

// ── Tabs ──
function showTab(t){{
  ['stats','detail','top'].forEach(id=>{{
    document.getElementById('tab-'+id).style.display=id===t?'block':'none';
  }});
  document.querySelectorAll('.stab').forEach((el,i)=>{{
    el.classList.toggle('active',['stats','detail','top'][i]===t);
  }});
}}

// ── Top accounts table ──
(function buildTopTable(){{
  const tbody = document.getElementById('top-tbody');
  tbody.innerHTML = TOP.map(r=>`
    <tr onclick="focusNode('${{r.id}}')" style="cursor:pointer">
      <td title="${{r.id}}" style="color:${{r.suspicious?'#c0392b':r.in_cycle?'#b07800':'#1a1a1a'}}">${{r.id.length>16?r.id.slice(0,15)+'…':r.id}}</td>
      <td style="color:#1e7e34">${{fmtAmt(r.inflow)}}</td>
      <td style="color:#c0392b">${{fmtAmt(r.outflow)}}</td>
      <td>${{r.txn_count.toLocaleString()}}</td>
      <td>${{r.suspicious?'<span class="susp-flag">⚠ Susp</span>':r.in_cycle?'<span class="cycle-flag">↻ Cycle</span>':'—'}}</td>
    </tr>`).join('');
}})();

function focusNode(id){{
  showTab('detail');
  network.focus(id,{{scale:1.5,animation:{{duration:500}}}});
  network.selectNodes([id]);
  const nd = ALL_NODES.find(n=>n.id===id);
  if(nd) showNodeDetail(nd);
}}

// ── Search ──
function searchNode(q){{
  if(!q){{clearSearch();return;}}
  q=q.toLowerCase();
  const matches=ALL_NODES.filter(n=>n.id.toLowerCase().includes(q)).map(n=>n.id);
  nodesDS.update(ALL_NODES.map(n=>{{return {{id:n.id,hidden:!matches.includes(n.id)}};}}));
  edgesDS.update(ALL_EDGES.map(e=>{{return {{id:e.id,hidden:!(matches.includes(e.from)&&matches.includes(e.to))}};}}));
  if(matches.length===1) network.focus(matches[0],{{scale:1.5,animation:{{duration:400}}}});
}}
function clearSearch(){{
  document.getElementById('search-input').value='';
  filterView(currentFilter);
}}

// ── Zoom ──
function zoomIn(){{network.moveTo({{scale:network.getScale()*1.3,animation:{{duration:200}}}});}}
function zoomOut(){{network.moveTo({{scale:network.getScale()*0.77,animation:{{duration:200}}}});}}

// ── Format ──
function fmtAmt(n){{
  if(n>=1e9) return '$'+(n/1e9).toFixed(2)+'B';
  if(n>=1e6) return '$'+(n/1e6).toFixed(2)+'M';
  if(n>=1e3) return '$'+(n/1e3).toFixed(1)+'K';
  return '$'+Math.round(n).toLocaleString();
}}
</script>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

def fmt_amt(n):
    if n >= 1e9: return f"${n/1e9:.2f}B"
    if n >= 1e6: return f"${n/1e6:.2f}M"
    if n >= 1e3: return f"${n/1e3:.1f}K"
    return f"${n:,.0f}"

# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"✗  File not found: {csv_path}")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  Transaction Network Analyzer")
    print(f"{'='*55}")
    print(f"  File: {csv_path} ({csv_path.stat().st_size/1e6:.1f} MB)")

    # Peek at headers
    peek = pd.read_csv(csv_path, nrows=0)
    headers = list(peek.columns)
    print(f"\n  Detected columns: {headers}")

    col_from = require_col(headers, "sender",   args.sender,   csv_path)
    col_to   = require_col(headers, "receiver", args.receiver, csv_path)
    col_amt  = require_col(headers, "amount",   args.amount,   csv_path)
    col_ts   = detect_col(headers, "timestamp", args.timestamp)
    col_susp = detect_col(headers, "suspicious",args.suspicious)

    print(f"\n  Column mapping:")
    print(f"    sender      → '{col_from}'")
    print(f"    receiver    → '{col_to}'")
    print(f"    amount      → '{col_amt}'")
    print(f"    timestamp   → '{col_ts or 'not found'}'")
    print(f"    suspicious  → '{col_susp or 'not found (will auto-flag)'}'")

    # Stream & aggregate
    agg = StreamAggregator(
        col_from=col_from, col_to=col_to, col_amount=col_amt,
        col_ts=col_ts, col_susp=col_susp,
        susp_pct=args.susp_pct, chunk_size=args.chunk_size,
    )
    agg.ingest(csv_path)

    # Build graph
    G, total_edges = build_graph(agg, sample_limit=args.sample)
    sampled = total_edges > args.sample

    # Analytics
    stats = compute_analytics(G, agg)

    # Top nodes
    top = top_nodes(G, n=20)

    # Export
    out = Path(args.output)
    build_html(G, stats, top, out, csv_path.name, sampled, total_edges)

    print(f"\n{'='*55}")
    print(f"  ✓  Report saved → {out.resolve()}")
    print(f"     Open in any browser — fully self-contained.")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
