#!/usr/bin/env python3
"""
build_exports.py — regenerate the derived artifacts from README.MD (the source of truth).

Parses the main threat-actor table + the deepfake table (+ Appendix A TTP definitions)
and emits three files:
  - index.html                              interactive, searchable Pages homepage
  - tracker.json                            structured data (machine-readable)
  - stix/threat-actors-ai-stix2.1.json      complete STIX 2.1 bundle

Deterministic + idempotent: UUIDv5 IDs and content-derived stable timestamps (never now()),
stdlib only. Run from the repo root:  python tools/build_exports.py
"""
import json, re, sys, uuid, hashlib
from pathlib import Path

ROOT = Path(".")
NS = uuid.UUID("6d8b7e2a-1c4f-5a9d-b3e6-0f2a7c9d4e11")  # fixed namespace for stable IDs
EPOCH = "2024-01-01T00:00:00.000Z"
MON = {m[:3]: i+1 for i, m in enumerate(
    ["January","February","March","April","May","June","July","August","September","October","November","December"])}

# ---------- parsing ----------
def read(p): return (ROOT / p).read_text(encoding="utf-8")

def parse_table(lines, header_startswith, ncols):
    hdr = next(i for i, l in enumerate(lines) if l.startswith(header_startswith))
    rows = []
    i = hdr + 2
    while i < len(lines) and lines[i].startswith("|"):
        cells = [c.strip() for c in lines[i].split("|")[1:-1]]
        if len(cells) >= ncols and cells[0]:
            rows.append(cells[:ncols])
        i += 1
    return rows

def clean(s):
    s = re.sub(r"<br\s*/?>", " ", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"\1", s)  # md link -> text
    return re.sub(r"\s+", " ", s).strip()

def urls_in(s): return re.findall(r"https?://[^\s\)\]]+", s)

def md_links(s): return re.findall(r"\[([^\]]+)\]\((https?://[^)]+)\)", s)

def parse_ttp(cell):
    """Return list of {label, mitre:[ids], text} per <br><br> chunk."""
    out = []
    for chunk in re.split(r"<br\s*/?>\s*<br\s*/?>", cell):
        chunk = chunk.strip()
        if not chunk: continue
        labels = re.findall(r"\*\*(.+?)\*\*", chunk)
        ids = re.findall(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b", chunk)
        # technique name: text after the id up to <br> or end
        names = {}
        for m in re.finditer(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b\s*-\s*([^<|]+)", chunk):
            names[m.group(1)] = m.group(2).strip().rstrip(".")
        out.append({"labels": [clean(x) for x in labels], "mitre": ids, "names": names})
    return out

def parse_appendix(text):
    defs = {}
    m = re.search(r"## Appendix A", text)
    if not m: return defs
    seg = text[m.start():]
    seg = seg.split("# !!!")[0]
    for mm in re.finditer(r"\*\*(.+?)[:\*]{1,3}\s*(.+?)(?:\(CREDIT[^)]*\))?\s*(?:\n|$)", seg):
        label = clean(mm.group(1)); body = clean(mm.group(2))
        if label and body: defs[label.lower()] = body[:600]
    return defs

DOMAIN_ORG = {
    "anthropic.com":"Anthropic","openai.com":"OpenAI","cloud.google.com":"Google Threat Intelligence Group",
    "blog.google":"Google","microsoft.com":"Microsoft","sysdig.com":"Sysdig","crowdstrike.com":"CrowdStrike",
    "welivesecurity.com":"ESET","eset.com":"ESET","securelist.com":"Kaspersky","sentinelone.com":"SentinelOne",
    "proofpoint.com":"Proofpoint","checkpoint.com":"Check Point","research.checkpoint.com":"Check Point Research",
    "huntress.com":"Huntress","unit42.paloaltonetworks.com":"Palo Alto Networks Unit 42","paloaltonetworks.com":"Palo Alto Networks",
    "mandiant.com":"Mandiant","ncsc.gov.uk":"NCSC UK","ic3.gov":"FBI IC3","fbi.gov":"FBI","recordedfuture.com":"Recorded Future",
    "hunt.io":"Hunt.io","sygnia.co":"Sygnia","theregister.com":"The Register","thehackernews.com":"The Hacker News",
    "resecurity.com":"Resecurity","jfrog.com":"JFrog","symantec-enterprise-blogs.security.com":"Symantec","security.com":"Symantec",
    "trendmicro.com":"Trend Micro","scmp.com":"South China Morning Post","wsj.com":"Wall Street Journal",
    "infosecurity-magazine.com":"Infosecurity Magazine","state.gov":"US Dept of State","cnbc.com":"CNBC",
    "aws.amazon.com":"Amazon","mp.weixin.qq.com":"WeChat (Chinese vendor)",
}
def org_for(url):
    m = re.match(r"https?://([^/]+)/?", url or "")
    host = (m.group(1) if m else "").lower().lstrip("www.")
    for d, o in DOMAIN_ORG.items():
        if d in host: return o
    return host or "Unknown source"

MALWARE = ["PROMPTSTEAL","LameHug","JADEPUFFER","TuxBot v3","TuxBot","QUIETVAULT","PROMPTFLUX","PROMPTSPY","BusySnake",
           "VenomRAT","CANFAIL","LONGSTREAM","BIGMACHO","Funklocker","OSSTUN","COINBAIT","Rhadamanthys","zgRAT","DOILoader",
           "SparkCat","Win32/Wkysol","NetSupport","LokiBot","ModiLoader","DBatLoader","CleanUpLoader","Dunihi","AsyncRAT"]

def first_last(span):
    """'Mon YYYY – Mon YYYY' / 'Mon YYYY' -> (first_iso, last_iso) or (None,None)."""
    if not span or span.lower() == "unknown": return None, None
    def ym(tok):
        tok = tok.strip()
        m = re.search(r"([A-Z][a-z]{2})\s+(\d{4})", tok)
        if m: return int(m.group(2)), MON.get(m.group(1))
        m = re.search(r"\b(\d{4})\b", tok)
        if m: return int(m.group(1)), 1
        return None
    parts = re.split(r"\s*[–-]\s*", span)
    a = ym(parts[0]); b = ym(parts[-1]) if len(parts) > 1 else a
    def iso(v, end=False):
        if not v: return None
        y, mo = v; mo = mo or (12 if end else 1)
        return f"{y:04d}-{mo:02d}-01T00:00:00.000Z"
    return iso(a, False), iso(b, True)

def reported_iso(rep):
    if not rep or rep.lower() == "unknown": return EPOCH
    m = re.search(r"([A-Z][a-z]{2})\s+(\d{4})", rep)
    if m: return f"{int(m.group(2)):04d}-{MON.get(m.group(1),1):02d}-01T00:00:00.000Z"
    m = re.search(r"\b(\d{4})\b", rep)
    return f"{int(m.group(1)):04d}-01-01T00:00:00.000Z" if m else EPOCH

def _min_ym(s):
    """Earliest YYYYMM integer found in s (Mon YYYY or bare YYYY), or None."""
    keys = []
    for m in re.finditer(r"([A-Z][a-z]{2})\s+(\d{4})", s or ""):
        keys.append(int(m.group(2)) * 100 + MON.get(m.group(1), 1))
    for m in re.finditer(r"\b(\d{4})\b", s or ""):
        y = int(m.group(1))
        if not any(k // 100 == y for k in keys): keys.append(y * 100 + 1)
    return min(keys) if keys else None

def date_key(v):
    """Numeric sort key (YYYYMM) for a date/range cell; None for Unknown/empty (sorts last)."""
    return None if (not v or v.strip().lower() == "unknown") else _min_ym(v)

# ---------- build structured records ----------
def build_records():
    txt = read("README.MD"); lines = txt.split("\n")
    appendix = parse_appendix(txt)
    main = parse_table(lines, "| Name", 7)
    deep = parse_table(lines, "| Year and Month", 7)
    recs = []
    for c in main:
        name, akas, brief, ttp, link, rep, act = c
        recs.append({"table":"main","name":clean(name),"akas":clean(akas),"brief_md":brief,"brief":clean(brief),
                     "ttp_md":ttp,"ttp":parse_ttp(ttp),"links":md_links(brief)+md_links(link)+[("",u) for u in urls_in(link)],
                     "reported":rep,"activity":act})
    for c in deep:
        ym, actor, victim, brief, ttp, link, rep = c
        recs.append({"table":"deepfake","name":clean(actor) or "UnSub","akas":"","victim":clean(victim),"brief_md":brief,
                     "brief":clean(brief),"ttp_md":ttp,"ttp":parse_ttp(ttp),
                     "links":md_links(brief)+md_links(link)+[("",u) for u in urls_in(link)],
                     "reported":rep,"activity":ym})
    return recs, appendix

# ---------- STIX ----------
def sid(t, key): return f"{t}--{uuid.uuid5(NS, t+':'+key)}"
def sdo(t, key, **kw):
    o = {"type":t,"spec_version":"2.1","id":sid(t,key),"created":kw.pop("created",EPOCH),
         "modified":kw.pop("modified",kw.get("created",EPOCH) if False else None) or EPOCH}
    o.update({k:v for k,v in kw.items() if v not in (None,[],"")})
    return o

def build_stix(recs, appendix):
    objs = {}   # id -> obj (dedup)
    reports = {}  # url -> {name, org, created, refs:set}  (a report can cover many actors)
    def add(o): objs.setdefault(o["id"], o)
    rels = {}
    def rel(src, tgt, rtype):
        rid = sid("relationship", f"{rtype}:{src}:{tgt}")
        rels.setdefault(rid, {"type":"relationship","spec_version":"2.1","id":rid,"created":EPOCH,"modified":EPOCH,
                              "relationship_type":rtype,"source_ref":src,"target_ref":tgt})
    for r in recs:
        created = reported_iso(r["reported"])
        fs, ls = first_last(r["activity"])
        aliases = [a.strip() for a in re.split(r"[,/]", r["akas"]) if a.strip() and a.strip().lower() not in ("unknown","n/a")]
        exts = []
        seen_u = set()
        for text, url in r["links"]:
            if url and url not in seen_u and url.startswith("http"):
                seen_u.add(url); exts.append({"source_name":org_for(url),"url":url,**({"description":text} if text else {})})
        is_id = sid("intrusion-set", r["name"])
        iset = {"type":"intrusion-set","spec_version":"2.1","id":is_id,"created":created,"modified":created,
                "name":r["name"],"description":r["brief"][:1500]}
        if aliases: iset["aliases"] = aliases
        if fs: iset["first_seen"] = fs
        if ls: iset["last_seen"] = ls
        if exts: iset["external_references"] = exts
        if r["table"] == "deepfake": iset.setdefault("labels", []).append("deepfake")
        add(iset)
        # attack-patterns
        ap_ids = []
        for chunk in r["ttp"]:
            for lbl in chunk["labels"]:
                ap = sdo("attack-pattern", "llm:"+lbl.lower(), name=lbl,
                         description=appendix.get(lbl.lower(), "Custom LLM-themed TTP (see Appendix A)."))
                ap["x_llm_ttp"] = True
                add(ap); ap_ids.append(ap["id"])
            for mid in chunk["mitre"]:
                nm = chunk["names"].get(mid, mid)
                ap = sdo("attack-pattern", "mitre:"+mid, name=nm,
                         external_references=[{"source_name":"mitre-attack","external_id":mid,
                             "url":f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/"}])
                add(ap); ap_ids.append(ap["id"])
        for ap in sorted(set(ap_ids)): rel(is_id, ap, "uses")
        # malware
        mw_ids = []
        for fam in MALWARE:
            if re.search(r"\b"+re.escape(fam)+r"\b", r["brief_md"], re.I):
                mw = sdo("malware", fam.lower(), name=fam, is_family=True)
                add(mw); mw_ids.append(mw["id"])
        for mw in sorted(set(mw_ids)): rel(is_id, mw, "uses")
        # accumulate reports per source URL (one report may cover many actors)
        for text, url in r["links"]:
            if not url or not url.startswith("http"): continue
            rp = reports.setdefault(url, {"name":"","org":org_for(url),"created":created,"refs":set()})
            if text and (not rp["name"] or len(text) > len(rp["name"])): rp["name"] = text
            rp["refs"].update([is_id] + ap_ids + mw_ids)
            if created < rp["created"]: rp["created"] = created
    # emit reports + identities
    for url, rp in reports.items():
        ident = sdo("identity", "org:"+rp["org"], name=rp["org"], identity_class="organization"); add(ident)
        add({"type":"report","spec_version":"2.1","id":sid("report","rpt:"+url),"created":rp["created"],"modified":rp["created"],
             "name":(rp["name"] or f"Report ({rp['org']})")[:200],"published":rp["created"],"created_by_ref":ident["id"],
             "object_refs":sorted(rp["refs"]),"external_references":[{"source_name":rp["org"],"url":url}]})
    allobjs = list(objs.values()) + list(rels.values())
    allobjs.sort(key=lambda o: (o["type"], o["id"]))
    return {"type":"bundle","id":sid("bundle","threat-actors-ai"),"objects":allobjs}

# ---------- HTML ----------
def build_html(recs):
    data = []
    for r in recs:
        data.append({"name":r["name"],"akas":r["akas"],"reported":r["reported"],"activity":r["activity"],
                     "rsort":date_key(r["reported"]),"asort":date_key(r["activity"]),
                     "brief":r["brief"],"ttp":clean(r["ttp_md"]),"table":r["table"],
                     "links":[{"t":t or org_for(u),"u":u} for t,u in r["links"] if u.startswith("http")][:4]})
    payload = json.dumps(data, ensure_ascii=False)
    return HTML_TEMPLATE.replace("__DATA__", payload).replace("__N__", str(len(data)))

HTML_TEMPLATE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Threat Actors' Use of AI — Tracker</title>
<style>
:root{--bg:#0b0e14;--fg:#e6e6e6;--mut:#8a93a6;--line:#232838;--accent:#00e5ff;--card:#141925}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:18px 20px;border-bottom:1px solid var(--line)}h1{margin:0 0 4px;font-size:20px}
.sub{color:var(--mut);font-size:13px}.sub a{color:var(--accent);text-decoration:none}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
input[type=search],select{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:13px}
input[type=search]{min-width:260px;flex:1}
.cnt{color:var(--mut);font-size:12px}.cols{display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--mut)}
.cols label{cursor:pointer}.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;min-width:900px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{position:sticky;top:0;background:var(--card);cursor:pointer;white-space:nowrap;font-size:12px;color:var(--mut);border-bottom:1px solid var(--line)}
th:hover{color:var(--fg)}tr:hover td{background:#0f131c}
td.name{font-weight:600;white-space:nowrap}.aka,.ttp{color:var(--mut);font-size:12.5px}
.date{white-space:nowrap;font-variant-numeric:tabular-nums}.unk{color:#5b6478}
.brief{max-width:640px}.brief.clip{max-height:4.4em;overflow:hidden;position:relative}
.more{color:var(--accent);cursor:pointer;font-size:12px}
.pill{display:inline-block;background:#0f1a1e;border:1px solid #17323a;color:var(--accent);border-radius:20px;padding:1px 8px;font-size:11px;margin-right:4px}
a.src{color:var(--accent);text-decoration:none;font-size:12px;display:block}
footer{padding:16px 20px;color:var(--mut);font-size:12px;border-top:1px solid var(--line)}
footer a{color:var(--accent);text-decoration:none}
</style></head><body>
<header><h1>Threat Actors' Use of Artificial Intelligence — Tracker</h1>
<div class=sub>Confirmed real-world threat-actor use of AI/LLMs, mapped to TTPs. Source of truth: the
<a href="README.MD">README table</a> · <a href="Sources.md">Sources</a> ·
<a href="stix/threat-actors-ai-stix2.1.json">⬇ STIX 2.1 bundle</a> ·
<a href="tracker.json">JSON</a> · <a href="https://cybershujin.com" target=_blank rel=noopener>cybershujin.com</a> ·
<a href="https://www.linkedin.com/in/cybershujin" target=_blank rel=noopener>LinkedIn</a></div></header>
<div class=bar>
<input id=q type=search placeholder="Search actors, AKAs, TTPs, briefs…">
<select id=tbl><option value="">All tables</option><option value=main>Main</option><option value=deepfake>Deepfake</option></select>
<span class=cnt id=cnt></span>
<span class=cols id=cols></span>
</div>
<div class=wrap><table id=t><thead><tr id=hr></tr></thead><tbody id=tb></tbody></table></div>
<footer>Maintained by <a href="https://cybershujin.com" target=_blank rel=noopener>cybershujin.com</a> · <a href="https://www.linkedin.com/in/cybershujin" target=_blank rel=noopener>LinkedIn @cybershujin</a><br>Generated from README.MD · __N__ entries · auto-updated on each commit.</footer>
<script>
const DATA=__DATA__;
const COLS=[["name","Name"],["akas","AKAs"],["reported","Reported"],["activity","Activity Span"],["brief","Brief"],["ttp","TTP"],["links","Sources"]];
let vis={name:1,akas:1,reported:1,activity:1,brief:1,ttp:0,links:1},sortK="name",sortDir=1;
const hr=document.getElementById("hr"),tb=document.getElementById("tb"),cols=document.getElementById("cols");
COLS.forEach(([k,l])=>{const cb=document.createElement("label");cb.innerHTML=`<input type=checkbox ${vis[k]?"checked":""} data-k="${k}"> ${l}`;cols.appendChild(cb);});
cols.onchange=e=>{vis[e.target.dataset.k]=e.target.checked?1:0;render();};
function head(){hr.innerHTML="";COLS.forEach(([k,l])=>{if(!vis[k])return;const th=document.createElement("th");th.textContent=l+(sortK===k?(sortDir>0?" ▲":" ▼"):"");th.onclick=()=>{if(sortK===k)sortDir*=-1;else{sortK=k;sortDir=1;}render();};hr.appendChild(th);});}
function dcell(v){return v&&v.toLowerCase()!=="unknown"?`<span class=date>${v}</span>`:`<span class="date unk">Unknown</span>`;}
function render(){
 const q=document.getElementById("q").value.toLowerCase(),tf=document.getElementById("tbl").value;
 let rows=DATA.filter(d=>(!tf||d.table===tf)&&(!q||JSON.stringify(d).toLowerCase().includes(q)));
 rows.sort((a,b)=>{
   if(sortK==="reported"||sortK==="activity"){
     const ka=sortK==="reported"?a.rsort:a.asort, kb=sortK==="reported"?b.rsort:b.asort;
     if(ka==null&&kb==null)return 0; if(ka==null)return 1; if(kb==null)return -1;  // Unknown always last
     return (ka-kb)*sortDir;
   }
   return ((a[sortK]||"")+"").localeCompare((b[sortK]||"")+"")*sortDir;});
 head();tb.innerHTML="";
 for(const d of rows){const tr=document.createElement("tr");let h="";
  for(const [k,l] of COLS){if(!vis[k])continue;
   if(k==="name")h+=`<td class=name>${esc(d.name)}${d.table==="deepfake"?' <span class=pill>deepfake</span>':''}</td>`;
   else if(k==="akas")h+=`<td class=aka>${esc(d.akas)}</td>`;
   else if(k==="reported"||k==="activity")h+=`<td>${dcell(d[k])}</td>`;
   else if(k==="brief")h+=`<td><div class="brief clip">${esc(d.brief)}</div><span class=more>more ▾</span></td>`;
   else if(k==="ttp")h+=`<td class=ttp>${esc(d.ttp)}</td>`;
   else if(k==="links")h+=`<td>${d.links.map(x=>`<a class=src href="${x.u}" target=_blank rel=noopener>${esc(x.t)}</a>`).join("")}</td>`;
  }
  tr.innerHTML=h;tb.appendChild(tr);}
 document.getElementById("cnt").textContent=rows.length+" / "+DATA.length;
 tb.querySelectorAll(".more").forEach(m=>m.onclick=()=>{const b=m.previousElementSibling;b.classList.toggle("clip");m.textContent=b.classList.contains("clip")?"more ▾":"less ▴";});
}
function esc(s){return (s||"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
document.getElementById("q").oninput=render;document.getElementById("tbl").onchange=render;render();
</script></body></html>"""

# ---------- main ----------
def main():
    recs, appendix = build_records()
    (ROOT/"tracker.json").write_text(json.dumps({"generated_from":"README.MD","count":len(recs),
        "entries":[{k:r[k] for k in ("table","name","akas","brief","ttp_md","reported","activity")} for r in recs]},
        indent=1, ensure_ascii=False), encoding="utf-8")
    bundle = build_stix(recs, appendix)
    (ROOT/"stix").mkdir(exist_ok=True)
    (ROOT/"stix"/"threat-actors-ai-stix2.1.json").write_text(json.dumps(bundle, indent=1, ensure_ascii=False), encoding="utf-8")
    (ROOT/"index.html").write_text(build_html(recs), encoding="utf-8")
    types = {}
    for o in bundle["objects"]: types[o["type"]] = types.get(o["type"],0)+1
    print(f"entries={len(recs)}  stix_objects={len(bundle['objects'])}  {types}")

if __name__ == "__main__":
    main()
