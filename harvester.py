#!/usr/bin/env python3
"""
harvester.py — VPN feed harvester (Phase 1, step 1: feed only, no app).

Pipeline (tester core = phase0_core.py, copied verbatim from the proven
Phase 0 script):
  1. HARVEST  every source in sources.txt (file order = priority), tagging
              each config with the source it came from.
  2. DEDUP    globally; the copy from the highest-priority source wins.
  3. TCP      fast connect probes, in priority order (capped by --tcp-limit).
  4. CORE     real sing-box handshake + service probes, in PRIORITY ORDER
              (source priority, then fastest TCP first) up to --core-limit
              and a wall-clock budget so the CI job always finishes.
  5. SPEED    optional: download-speed sample on the top --speed-cap working
              nodes by proxy latency only (bounds runtime).
  6. PUBLISH  feed/working.txt + feed/working.b64 (subscription format),
              feed/stats.json, and one appended row in feed/history.csv
              (the per-cycle yield record).

Why priority order matters (measured in Phase 0): curated sources pass the
core test ~5x more often than raw mega-pools (NoMoreWalls 34% vs mega-pool
6.9%), and node survival is only ~31%/day — so the feed refreshes every
3 hours and always spends its test budget on the best sources first.

Stdlib only. Python 3.10+.
Usage:
  python harvester.py                      # full cycle (needs ./sing-box)
  python harvester.py --no-core            # harvest + TCP only (dry run)
  SINGBOX=/path/sing-box python harvester.py --core-limit 800 --speed
"""
import argparse, base64, csv, json, os, re, statistics, sys, time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import phase0_core as core

# ---------------------------------------------------------------- sources
def short_source_name(url):
    """Human label for stats: owner/repo, v2nodes/<cc>, tg/<channel>, else host."""
    try:
        u = urllib.parse.urlsplit(url)
        host, path = u.netloc.lower(), u.path
        if "v2nodes.com" in host:
            m = re.search(r"/country/([a-z]+)/", path)
            return f"v2nodes/{m.group(1)}" if m else "v2nodes"
        if host == "t.me":
            return "tg/" + path.strip("/").split("/")[-1]
        if "github" in host:
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
        return host
    except Exception:
        return url[:40]

def load_sources(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                out.append({"prio": len(out), "url": s, "name": short_source_name(s)})
    return out

# ---------------------------------------------------------------- country heuristics
# Flag emoji are pairs of regional-indicator codepoints; also accept the
# "-XX-" / " XX " code style used in many remarks (e.g. "ss-GB-1451...").
_RI = {chr(0x1F1E6 + i): chr(ord("A") + i) for i in range(26)}
SEA_CODES = {"SG", "TH", "MY", "HK", "ID", "VN", "PH", "KH", "LA", "MM", "BN", "JP"}
_KNOWN_CODES = SEA_CODES | {"US", "GB", "NL", "DE", "FR", "AE", "IT", "KR", "TW",
                            "IN", "RU", "TR", "CA", "AU", "ES", "SE", "CH", "PL",
                            "UA", "KZ", "UZ", "AM", "AZ", "IR", "CN", "BR", "AR"}

def node_country(node):
    name = node.get("name") or ""
    letters = [_RI[c] for c in name if c in _RI]
    for i in range(0, len(letters) - 1, 2):
        code = letters[i] + letters[i + 1]
        if code in _KNOWN_CODES:
            return code
    m = re.search(r"[-_ \[\|]([A-Z]{2})[-_ \[\|\d]", name)
    if m and m.group(1) in _KNOWN_CODES:
        return m.group(1)
    return ""

# ---------------------------------------------------------------- stages
def harvest(sources):
    all_nodes, raw_count, per_source = [], 0, []
    for s in sources:
        entry = {"prio": s["prio"], "name": s["name"], "url": s["url"],
                 "links": 0, "kept_unique": 0, "error": ""}
        try:
            text = core.fetch_source(s["url"])
            links = core.extract_links(text)
            entry["links"] = len(links)
            raw_count += len(links)
            for link in links:
                n = core.parse_link(link)
                if n:
                    n["source"] = s["url"]
                    n["source_name"] = s["name"]
                    n["source_prio"] = s["prio"]
                    all_nodes.append(n)
            print(f"      [{s['prio']:2d}] {s['name']:<28} {len(links):>6} links", flush=True)
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"[:120]
            print(f"      [{s['prio']:2d}] {s['name']:<28} FETCH FAIL: {entry['error']}", flush=True)
        per_source.append(entry)
    return all_nodes, raw_count, per_source

def dedup_validate(all_nodes, per_source):
    seen, nodes = set(), []
    for n in all_nodes:                      # harvest order == priority order
        k = core.dedup_key(n)
        if k in seen:
            continue
        seen.add(k)
        errs, warns = core.validate(n)
        n["errors"], n["warnings"] = errs, warns
        nodes.append(n)
        per_source[n["source_prio"]]["kept_unique"] += 1
    return nodes

def tcp_stage(valid_nodes, workers, limit):
    """Probe in priority order (list is already priority-grouped); the cap
    keeps a giant mega-pool from eating the whole job's wall clock."""
    targets = valid_nodes if limit <= 0 else valid_nodes[:limit]
    print(f"[3/5] TCP probes on {len(targets)} format-valid configs "
          f"(workers={workers})...", flush=True)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(core.tcp_probe, n, 1, 2.5) for n in targets]
        done = 0
        for _ in as_completed(futs):
            done += 1
            if done % 1000 == 0:
                print(f"      {done}/{len(targets)}", flush=True)
    ok = [n for n in targets if n.get("tcp_ok")]
    print(f"      TCP reachable: {len(ok)}", flush=True)
    return ok

def core_stage(candidates, core_bin, budget, time_budget_s):
    """Core-test in (source priority, fastest TCP) order, in chunks so the
    wall-clock budget can stop us cleanly between chunks."""
    cands = sorted(candidates,
                   key=lambda x: (x["source_prio"], x.get("tcp_ms") or 99999))[:budget]
    print(f"[4/5] core handshake tests: {len(cands)} candidates "
          f"(priority order, budget {budget}, time budget {time_budget_s}s) "
          f"via {core_bin}", flush=True)
    t0 = time.time()
    tested, idx, CHUNK = 0, 0, 30
    while idx < len(cands):
        if tested and time.time() - t0 > time_budget_s:
            print(f"      time budget hit after {tested} tests — stopping", flush=True)
            break
        chunk = cands[idx:idx + CHUNK]
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(core.core_test, n, core_bin, 24080 + ((idx + j) % 3), False)
                    for j, n in enumerate(chunk)]
            for _ in as_completed(futs):
                pass
        idx += len(chunk)
        tested += len(chunk)
        ok = sum(1 for n in cands[:idx] if n.get("core") == "ok")
        print(f"      {tested}/{len(cands)} tested, {ok} working so far", flush=True)
    return [n for n in cands if n.get("core") == "ok"], len([n for n in cands[:idx]
                                                            if n.get("core") in ("ok", "fail")])

def speed_wave(working, core_bin, cap):
    """Re-run the top-`cap` working nodes by proxy latency with the speed
    probe on. Guarded: if a re-run flakes, the first pass's result stands."""
    top = sorted(working, key=lambda x: x.get("proxy_ms") or 99999)[:cap]
    if not top:
        return
    print(f"      speed samples on top {len(top)} working nodes by latency...", flush=True)
    saved = {id(n): (n.get("core"), n.get("services"), n.get("proxy_ms"),
                     n.get("udp_ok"), n.get("udp_ms")) for n in top}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(core.core_test, n, core_bin, 24080 + (i % 3), True)
                for i, n in enumerate(top)]
        for _ in as_completed(futs):
            pass
    for n in top:
        if n.get("core") != "ok":
            c, svc, ms, udp_ok, udp_ms = saved[id(n)]
            n["core"], n["services"], n["proxy_ms"] = c, svc, ms
            n["udp_ok"], n["udp_ms"] = udp_ok, udp_ms
            n["mbps"] = 0

# ---------------------------------------------------------------- outputs
def write_outputs(outdir, working, meta):
    os.makedirs(outdir, exist_ok=True)
    ranked = sorted(working, key=lambda x: (-(x.get("score_general") or 0),
                                            x.get("proxy_ms") or 99999))
    txt = "".join(n["raw"] + "\n" for n in ranked)
    with open(os.path.join(outdir, "working.txt"), "w", encoding="utf-8") as f:
        f.write(txt)
    with open(os.path.join(outdir, "working.b64"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode(txt.encode("utf-8")).decode("ascii"))

    countries, sea_total = {}, 0
    for n in working:
        cc = node_country(n)
        if cc:
            countries[cc] = countries.get(cc, 0) + 1
            if cc in SEA_CODES:
                sea_total += 1
    proxy = [n["proxy_ms"] for n in working if n.get("proxy_ms")]
    stats = dict(meta)
    stats.update({
        "sea_working": {"total": sea_total,
                        "by_country": dict(sorted(countries.items(),
                                                  key=lambda kv: -kv[1]))},
        "median_proxy_ms": round(statistics.median(proxy), 1) if proxy else None,
        "top10": [{"protocol": n["protocol"], "name": n.get("name") or n["host"],
                   "country": node_country(n), "proxy_ms": n.get("proxy_ms"),
                   "mbps": n.get("mbps"), "score": n.get("score_general"),
                   "source": n.get("source_name")} for n in ranked[:10]],
    })
    with open(os.path.join(outdir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)

    hist_path = os.path.join(outdir, "history.csv")
    new_file = not os.path.isfile(hist_path) or os.path.getsize(hist_path) == 0
    with open(hist_path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["timestamp", "harvested", "unique", "valid", "tcp_ok",
                        "core_tested", "working", "fast_lt100ms", "sea_working",
                        "median_proxy_ms"])
        w.writerow([meta["timestamp"], meta["harvested"], meta["unique"],
                    meta["valid"], meta["tcp_ok"], meta["core_tested"],
                    len(working), meta["fast_lt100ms"], sea_total,
                    stats["median_proxy_ms"] if stats["median_proxy_ms"] is not None else ""])
    return stats

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="VPN feed harvester (Phase 1 step 1)")
    ap.add_argument("--sources", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "sources.txt"))
    ap.add_argument("--out", default=os.path.join(os.getcwd(), "feed"),
                    help="output directory (default ./feed)")
    ap.add_argument("--workers", type=int, default=64, help="TCP probe threads")
    ap.add_argument("--tcp-limit", type=int, default=15000,
                    help="max format-valid configs to TCP-probe, priority order (<=0 = all)")
    ap.add_argument("--core", help="path to sing-box binary (or set SINGBOX env)")
    ap.add_argument("--no-core", action="store_true", help="skip handshake tests (dry run)")
    ap.add_argument("--core-limit", type=int, default=800,
                    help="max nodes to core-test, priority order (default 800)")
    ap.add_argument("--core-time-budget", type=int, default=1200,
                    help="stop starting core tests after this many seconds (default 1200)")
    ap.add_argument("--speed", action="store_true", help="speed-sample the fastest working nodes")
    ap.add_argument("--speed-cap", type=int, default=60,
                    help="how many working nodes get a speed sample (default 60)")
    args = ap.parse_args()

    t_start = time.time()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sources = load_sources(args.sources)
    print(f"[1/5] harvesting {len(sources)} source(s) (order = priority)...", flush=True)
    all_nodes, raw_count, per_source = harvest(sources)
    print(f"[2/5] {raw_count} raw links; dedup + validate...", flush=True)
    nodes = dedup_validate(all_nodes, per_source)
    valid = [n for n in nodes if not n["errors"]]
    print(f"      {len(nodes)} unique ({len(valid)} format-valid)", flush=True)

    tcp_ok = tcp_stage(valid, args.workers, args.tcp_limit)

    working, core_tested = [], 0
    core_bin = None if args.no_core else core.find_core(args.core)
    if core_bin:
        working, core_tested = core_stage(tcp_ok, core_bin, args.core_limit,
                                          args.core_time_budget)
        if args.speed and working:
            speed_wave(working, core_bin, args.speed_cap)
    elif args.no_core:
        print("[4/5] core stage skipped by --no-core (working list will be empty)", flush=True)
    else:
        print("[4/5] WARNING: no sing-box binary found — core stage SKIPPED. "
              "Set SINGBOX or put ./sing-box next to this script.", flush=True)

    print("[5/5] scoring + writing feed...", flush=True)
    core.score_nodes(nodes)
    fast = [n for n in working if (n.get("tcp_ms") or 99999) < 100]
    meta = {"timestamp": ts, "harvested": raw_count, "unique": len(nodes),
            "valid": len(valid), "tcp_ok": len(tcp_ok),
            "core_tested": core_tested, "working": len(working),
            "fast_lt100ms": len(fast), "sources": per_source,
            "elapsed_s": round(time.time() - t_start, 1)}
    stats = write_outputs(args.out, working, meta)
    print(json.dumps({k: stats[k] for k in ("timestamp", "harvested", "unique",
                                            "tcp_ok", "core_tested", "working",
                                            "fast_lt100ms", "median_proxy_ms")},
                     indent=1))
    print(f"DONE in {meta['elapsed_s']}s -> {args.out}/working.txt, working.b64, "
          f"stats.json, history.csv")

if __name__ == "__main__":
    main()
