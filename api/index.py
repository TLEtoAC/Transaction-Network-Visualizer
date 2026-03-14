import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import networkx as nx
import math
import tempfile
from collections import defaultdict
import datetime

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(lifespan=lifespan)

# Allow CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALIASES = {
    "sender":    ["sender","from","source","payer","originator","account_from","from_account","from_id","sender_id","debit_account","account_id"],
    "receiver":  ["receiver","to","destination","payee","beneficiary","counterparty","account_to","to_account","to_id","receiver_id","credit_account","recipient"],
    "amount":    ["amount","value","sum","total","txn_amount","transaction_amount","amt","price","payment_amount"],
    "timestamp": ["timestamp","date","time","datetime","txn_date","transaction_date","created_at","date_time","trans_date","value_date"],
    "suspicious":["suspicious","is_suspicious","flagged","flag","fraud","is_fraud","alert","anomaly","risk_flag"],
}

def detect_col(headers, role):
    lh = {h.lower().strip().replace(" ", "_"): h for h in headers}
    for alias in ALIASES[role]:
        if alias in lh:
            return lh[alias]
    return None

def _safe(col): return col.replace(" ","_").replace("-","_").replace(".","_")

def _percentile(data, pct):
    s = sorted(data)
    if not s: return 0
    k = (len(s)-1) * pct / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f==c else s[f]*(c-k)+s[c]*(k-f)

@app.post("/api/analyze")
async def analyze_csv(
    file: UploadFile = File(...),
):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Must be a CSV file")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        try:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")

    try:
        # 1. Peek at columns
        df_head = pd.read_csv(tmp_path, nrows=0)
        headers = df_head.columns.tolist()

        c_from = detect_col(headers, "sender")
        c_to = detect_col(headers, "receiver")
        c_amt = detect_col(headers, "amount")
        c_ts = detect_col(headers, "timestamp")
        c_susp = detect_col(headers, "suspicious")

        if not c_from or not c_to or not c_amt:
            missing = []
            if not c_from: missing.append(f"sender (e.g. {', '.join(ALIASES['sender'][:3])})")
            if not c_to: missing.append(f"receiver (e.g. {', '.join(ALIASES['receiver'][:3])})")
            if not c_amt: missing.append(f"amount (e.g. {', '.join(ALIASES['amount'][:3])})")
            raise HTTPException(status_code=400, detail=f"Missing required columns. Not found: {', '.join(missing)}")

        # 2. Stream chunk aggregator
        chunk_size = 100_000
        edge_stats  = defaultdict(lambda: defaultdict(lambda: {"total": 0.0, "count": 0, "susp": 0}))
        node_vol    = defaultdict(lambda: {"inflow":0.0,"outflow":0.0,"txn_count":0,"susp_count":0})
        amounts_sample = []
        total_rows = 0
        total_amount = 0.0
        has_susp = False

        use_cols = [c_from, c_to, c_amt]
        if c_ts: use_cols.append(c_ts)
        if c_susp: use_cols.append(c_susp)

        for chunk in pd.read_csv(tmp_path, usecols=use_cols, chunksize=chunk_size, low_memory=False, on_bad_lines="skip"):
            chunk = chunk.dropna(subset=[c_from, c_to, c_amt])
            chunk[c_amt] = pd.to_numeric(chunk[c_amt].astype(str).str.replace(r"[$,\s]", "", regex=True), errors="coerce")
            chunk = chunk[chunk[c_amt] > 0].dropna(subset=[c_amt])
            
            total_rows += len(chunk)

            if len(amounts_sample) < 500_000:
                amounts_sample.extend(chunk[c_amt].tolist())

            susp_flags = None
            if c_susp and c_susp in chunk.columns:
                has_susp = True
                susp_flags = chunk[c_susp].astype(str).str.strip().str.lower().isin(
                    ["true","1","yes","y","flagged","fraud","suspicious"]
                )

            for i, row in enumerate(chunk.itertuples(index=False)):
                frm = str(getattr(row, _safe(c_from)))
                to = str(getattr(row, _safe(c_to)))
                amount = float(getattr(row, _safe(c_amt)))
                is_susp = bool(susp_flags.iloc[i]) if susp_flags is not None else False

                s = edge_stats[frm][to]
                s["total"] += amount
                s["count"] += 1
                if is_susp: s["susp"] += 1

                nf = node_vol[frm]
                nf["outflow"] += amount
                nf["txn_count"] += 1
                if is_susp: nf["susp_count"] += 1

                nt = node_vol[to]
                nt["inflow"] += amount
                nt["txn_count"] += 1
                if is_susp: nt["susp_count"] += 1

                total_amount += amount

        # Auto-suspicious
        if not has_susp and amounts_sample:
            threshold = _percentile(amounts_sample, 90) # Top 10%
            for frm, tos in edge_stats.items():
                for to, s in tos.items():
                    avg = s["total"] / s["count"] if s["count"] else 0
                    if avg >= threshold:
                        s["susp"] = s["count"]
            
        # 3. Graph
        # Keep sample limit reasonable for browser UI (Option 2 Vercel - usually 50k edges max)
        sample_limit = 50_000
        edge_items = [(f, t, s) for f, tos in edge_stats.items() for t, s in tos.items()]
        total_unique_edges = len(edge_items)
        if total_unique_edges > sample_limit:
            edge_items.sort(key=lambda x: x[2]["total"], reverse=True)
            edge_items = edge_items[:sample_limit]

        G = nx.DiGraph()
        for f, t, s in edge_items:
            G.add_edge(f, t, weight=s["total"], count=s["count"], susp_count=s["susp"], suspicious=s["susp"]>0, avg_amount=s["total"]/s["count"] if s["count"] else 0)

        for n in G.nodes():
            nv = node_vol.get(n, {})
            G.nodes[n]["inflow"] = nv.get("inflow", 0)
            G.nodes[n]["outflow"] = nv.get("outflow", 0)
            G.nodes[n]["txn_count"] = nv.get("txn_count", 0)
            G.nodes[n]["susp_count"] = nv.get("susp_count", 0)
            G.nodes[n]["net_flow"] = nv.get("inflow",0) - nv.get("outflow",0)

        # 4. Analytics
        try:
            pr = nx.pagerank(G, weight="weight", max_iter=200)
            for n, v in pr.items(): G.nodes[n]["pagerank"] = round(v, 6)
        except:
             pass

        sccs = sorted(nx.strongly_connected_components(G), key=len, reverse=True)
        large_sccs = [s for s in sccs if len(s) >= 3]
        total_nodes = G.number_of_nodes()
        meaningful_sccs = [s for s in large_sccs if 2 < len(s) <= max(6, total_nodes * 0.01)]
        
        cycle_nodes = set()
        for scc in meaningful_sccs: cycle_nodes.update(scc)
        for n in G.nodes(): G.nodes[n]["in_cycle"] = n in cycle_nodes

        susp_nodes = set()
        for n in G.nodes():
            nd = G.nodes[n]
            out_susp = sum(1 for nb in G.successors(n) if G[n][nb].get("suspicious", False))
            in_susp = sum(1 for nb in G.predecessors(n) if G[nb][n].get("suspicious", False))
            total_deg = (G.out_degree(n) + G.in_degree(n)) or 1
            susp_deg = out_susp + in_susp
            is_susp = (susp_deg / total_deg) > 0.25 or (nd.get("in_cycle") and susp_deg > 0)
            if is_susp: susp_nodes.add(n)
            nd["suspicious"] = is_susp
            nd["susp_edge_count"] = susp_deg

        # 5. Format JSON
        nodes_res = []
        for n in G.nodes():
            nd = G.nodes[n]
            nodes_res.append({
                "id": n,
                "name": n,
                "_susp": nd.get("suspicious", False),
                "_cycle": nd.get("in_cycle", False),
                "inflow": nd.get("inflow", 0),
                "outflow": nd.get("outflow", 0),
                "net": nd.get("net_flow", 0),
                "txnCount": nd.get("txn_count", 0),
                "suspCount": nd.get("susp_count", 0),
                "pagerank": nd.get("pagerank", 0),
            })

        edges_res = []
        for f, t, ed in G.edges(data=True):
            edges_res.append({
                "from": f,
                "to": t,
                "amount": ed.get("weight", 0),
                "count": ed.get("count", 0),
                "suspicious": ed.get("suspicious", False),
            })

        stats = {
            "total_nodes": total_nodes,
            "total_edges": total_unique_edges,
            "total_amount": total_amount,
            "susp_nodes": len(susp_nodes),
            "cycle_nodes": len(cycle_nodes),
            "n_cycles": len(meaningful_sccs),
            "sampled": total_unique_edges > sample_limit,
            "rendered_edges": G.number_of_edges(),
        }

        # top n
        top_list = [n for n in nodes_res]
        top_list.sort(key=lambda x: x["inflow"] + x["outflow"], reverse=True)
        top_n = top_list[:20]

        return {
            "nodes": nodes_res,
            "edges": edges_res,
            "stats": stats,
            "top": top_n
        }

    finally:
        os.remove(tmp_path)
