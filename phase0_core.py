#!/usr/bin/env python3
"""
phase0_core.py — tester core copied VERBATIM from vpn_phase0.py (Phase 0,
proven over 5 runs on a Myanmar PC), minus its CLI main(). The harvester
(harvester.py) imports these functions. Only adaptations vs the original:
  * find_core() also honours the SINGBOX environment variable (CI uses it).
  * main()/argparse removed — orchestration lives in harvester.py.
Node dicts additionally carry "source" / "source_name" / "source_prio" tags
set by the harvester at fetch time (used for priority-ordered core tests).

Original docstring follows.

vpn_phase0.py — Phase 0 feasibility tester for the AI-VPN aggregator idea.

What it does (NO AI, deliberately — Phase 0 measures whether the raw material works):
  1. FETCH    subscription URLs / raw files / local files -> share links
  2. PARSE    vless / vmess / trojan / ss / hysteria2 / tuic links into a normalised form
  3. VALIDATE deterministic format rules (bad Reality keys, missing passwords, bad ports...)
  4. DEDUP    same protocol+server+port+credential counted once
  5. TCP      DNS + TCP-connect latency probes (fast, threaded)
  6. CORE     (optional, needs a sing-box binary) real handshake through the node:
              service probes (Google 204 / Facebook / TikTok), UDP DNS probe,
              optional download-speed sample
  7. REPORT   results.json + results.csv + working_sub.txt + summary.md with the
              Phase 0 GATE verdict (usable %, <100 ms nodes, per-use-case counts)

Stdlib only. Python 3.9+.
Usage:
  python vpn_phase0.py --sources sources.txt
  python vpn_phase0.py --input somefile.txt --limit 200
  python vpn_phase0.py --sources sources.txt --speed --core-limit 60
Put sing-box (sing-box.exe on Windows) next to this script or on PATH to enable stage 6.
"""
import argparse, base64, csv, hashlib, json, math, os, re, socket, ssl, statistics
import subprocess, sys, tempfile, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) vpn-phase0/1.0"
LINK_RE = re.compile(r'(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s"\'<>\\]+', re.I)
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "aes-128-ctr", "aes-256-ctr", "aes-128-cfb",
    "aes-256-cfb", "chacha20-ietf", "rc4-md5", "none",
}

# ---------------------------------------------------------------- fetch / extract
def b64decode_loose(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)

def extract_links(text: str):
    """Pull share links out of plain text, or a whole-blob base64 subscription."""
    links = LINK_RE.findall(text)
    if links:
        return [l.rstrip(')",]') for l in links]
    blob = re.sub(r"\s+", "", text)
    if len(blob) > 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", blob or ""):
        try:
            decoded = b64decode_loose(blob).decode("utf-8", "replace")
            return [l.rstrip(')",]') for l in LINK_RE.findall(decoded)]
        except Exception:
            return []
    return []

def fetch_source(src: str, timeout=25):
    """src is an http(s) URL or a local file/dir path. Returns raw text."""
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    if os.path.isdir(src):
        out = []
        for name in sorted(os.listdir(src)):
            p = os.path.join(src, name)
            if os.path.isfile(p):
                out.append(open(p, encoding="utf-8", errors="replace").read())
        return "\n".join(out)
    with open(src, encoding="utf-8", errors="replace") as f:
        return f.read()

# ---------------------------------------------------------------- parse
def q1(qs, key, default=""):
    v = qs.get(key)
    return v[0] if v else default

def parse_link(link: str):
    """Return a normalised node dict, or None if the scheme is unsupported."""
    proto = link.split("://", 1)[0].lower()
    if proto == "hy2":
        proto = "hysteria2"
    node = {"raw": link, "protocol": proto, "name": "", "host": "", "port": 0,
            "credential": "", "transport": "tcp", "security": "",
            "sni": "", "params": {}}
    try:
        if proto == "vmess":
            data = json.loads(b64decode_loose(link.split("://", 1)[1].split("#")[0]))
            node["host"] = str(data.get("add", ""))
            node["port"] = int(data.get("port") or 0)
            node["credential"] = str(data.get("id", ""))
            node["name"] = str(data.get("ps", ""))
            node["transport"] = str(data.get("net", "tcp"))
            node["security"] = "tls" if str(data.get("tls", "")).lower() == "tls" else ""
            node["sni"] = str(data.get("sni") or data.get("host") or "")
            node["params"] = {"path": str(data.get("path", "")), "host_header": str(data.get("host", "")),
                              "alter_id": data.get("aid", 0), "cipher": str(data.get("scy", "auto"))}
            return node
        u = urllib.parse.urlsplit(link)
        frag = urllib.parse.unquote(u.fragment or "")
        node["name"] = frag
        qs = urllib.parse.parse_qs(u.query)
        hostport = u.netloc.rsplit("@", 1)[-1]
        if hostport.startswith("["):  # IPv6
            host, _, port = hostport[1:].partition("]:")
            node["host"], node["port"] = host, int(port or 0)
        else:
            host, _, port = hostport.partition(":")
            node["host"], node["port"] = host, int(port or 0)
        userinfo = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else ""
        if proto == "vless":
            node["credential"] = userinfo
            node["transport"] = q1(qs, "type", "tcp")
            node["security"] = q1(qs, "security")
            node["sni"] = q1(qs, "sni") or q1(qs, "peer")
            node["params"] = {k: q1(qs, k) for k in
                              ("flow", "pbk", "sid", "fp", "path", "host", "serviceName", "encryption", "spx")
                              if q1(qs, k)}
        elif proto == "trojan":
            node["credential"] = userinfo
            node["transport"] = q1(qs, "type", "tcp")
            node["security"] = "tls"
            node["sni"] = q1(qs, "sni") or q1(qs, "peer")
            node["params"] = {k: q1(qs, k) for k in ("path", "host", "serviceName") if q1(qs, k)}
        elif proto == "ss":
            cred = userinfo
            if ":" not in cred:  # fully-base64 userinfo
                try:
                    cred = b64decode_loose(cred).decode("utf-8", "replace")
                except Exception:
                    cred = ""
            method, _, password = cred.partition(":")
            node["credential"] = password
            node["params"] = {"method": method, "plugin": q1(qs, "plugin")}
            node["sni"] = ""
        elif proto == "hysteria2":
            node["credential"] = userinfo
            node["security"] = "tls"
            node["sni"] = q1(qs, "sni")
            node["params"] = {k: q1(qs, k) for k in ("insecure", "obfs", "obfs-password", "pinSHA256") if q1(qs, k)}
        elif proto == "tuic":
            node["credential"] = userinfo
            node["security"] = "tls"
            node["sni"] = q1(qs, "sni")
            node["params"] = {k: q1(qs, k) for k in
                              ("congestion_control", "udp_relay_mode", "alpn", "allow_insecure") if q1(qs, k)}
        return node
    except Exception as e:
        node["parse_error"] = f"{type(e).__name__}: {e}"
        return node

# ---------------------------------------------------------------- validate
def validate(node):
    """Deterministic format rules. Returns (errors, warnings). NO guessing, NO repair."""
    errs, warns = [], []
    if node.get("parse_error"):
        return [f"unparseable: {node['parse_error']}"], warns
    host, port, proto = node["host"], node["port"], node["protocol"]
    if not host:
        errs.append("missing server host")
    if not (1 <= port <= 65535):
        errs.append(f"bad port: {port}")
    cred = node["credential"]
    if proto in ("vless", "vmess"):
        if not UUID_RE.match(cred or ""):
            errs.append("uuid missing/not a UUID")
        if node["security"] == "reality":
            pbk = node["params"].get("pbk", "")
            try:
                raw = b64decode_loose(pbk) if pbk else b""
                if len(raw) != 32:
                    errs.append("reality pbk does not decode to 32 bytes")
            except Exception:
                errs.append("reality pbk is not valid base64url")
            sid = node["params"].get("sid", "")
            if sid and (len(sid) % 2 or len(sid) > 16 or not re.fullmatch(r"[0-9a-fA-F]*", sid)):
                errs.append("reality sid is not valid hex (<=8 bytes)")
            if not node["sni"]:
                warns.append("reality without SNI")
        if node["security"] == "tls" and not node["sni"]:
            warns.append("tls without SNI (host will be used)")
        if proto == "vless" and node["transport"] == "grpc" and not node["params"].get("serviceName"):
            warns.append("grpc without serviceName")
    elif proto == "ss":
        m = node["params"].get("method", "")
        if m not in SS_METHODS:
            errs.append(f"unknown ss method: {m or '(missing)'}")
        if not cred:
            errs.append("ss password missing")
    elif proto in ("trojan", "hysteria2"):
        if not cred:
            errs.append("password missing")
        if proto == "hysteria2" and not node["sni"]:
            warns.append("hysteria2 without SNI")
    elif proto == "tuic":
        uuid, _, pwd = (cred or "").partition(":")
        if not UUID_RE.match(uuid or ""):
            errs.append("tuic uuid missing/not a UUID")
        if not pwd:
            warns.append("tuic without password")
    return errs, warns

def dedup_key(node):
    return "|".join([node["protocol"], (node["host"] or "").lower(), str(node["port"]),
                     hashlib.sha256((node["credential"] or "").encode()).hexdigest()[:12]])

# ---------------------------------------------------------------- TCP probe
def tcp_probe(node, attempts=2, timeout=3.0):
    host, port = node["host"], node["port"]
    times = []
    dns_ms = None
    try:
        t0 = time.time()
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        dns_ms = (time.time() - t0) * 1000
        family, socktype, pr, _, addr = infos[0]
    except Exception:
        node["tcp_ok"] = False
        node["tcp_error"] = "DNS fail"
        return node
    for _ in range(attempts):
        try:
            t0 = time.time()
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(addr)
            times.append((time.time() - t0) * 1000)
            s.close()
        except Exception:
            pass
    node["dns_ms"] = round(dns_ms, 1)
    if times:
        node["tcp_ok"] = True
        node["tcp_ms"] = round(statistics.median(times), 1)
        node["tcp_jitter_ms"] = round(max(times) - min(times), 1) if len(times) > 1 else 0.0
    else:
        node["tcp_ok"] = False
        node["tcp_error"] = "connect fail/timeout"
    return node

# ---------------------------------------------------------------- sing-box build
def tls_block(node, reality=False):
    tls = {"enabled": True, "server_name": node["sni"] or node["host"]}
    fp = node["params"].get("fp") or "chrome"
    if reality:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
        tls["reality"] = {"enabled": True, "public_key": node["params"].get("pbk", ""),
                         "short_id": node["params"].get("sid", "")}
    else:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if node["params"].get("insecure") in ("1", "true"):
        tls["insecure"] = True
    return tls

def transport_block(node):
    t = node["transport"]
    if t == "ws":
        return {"type": "ws", "path": node["params"].get("path", "/"),
                "headers": {"Host": node["params"].get("host") or node["params"].get("host_header", "")}}
    if t == "grpc":
        return {"type": "grpc", "service_name": node["params"].get("serviceName", "")}
    if t in ("http", "h2"):
        return {"type": "http", "path": node["params"].get("path", "/"),
                "host": [node["params"].get("host", "")] if node["params"].get("host") else []}
    return None

def to_singbox_outbound(node):
    """Convert a normalised node to a sing-box outbound. None = unsupported in Phase 0."""
    p, params = node["protocol"], node["params"]
    base = {"tag": "proxy", "server": node["host"], "server_port": node["port"]}
    if p == "vless":
        ob = {**base, "type": "vless", "uuid": node["credential"],
              "flow": params.get("flow", ""), "packet_encoding": "xudp"}
        if node["security"] in ("tls", "reality"):
            ob["tls"] = tls_block(node, reality=node["security"] == "reality")
        tr = transport_block(node)
        if tr:
            ob["transport"] = tr
        return ob
    if p == "vmess":
        ob = {**base, "type": "vmess", "uuid": node["credential"],
              "alter_id": int(params.get("alter_id") or 0), "security": params.get("cipher", "auto")}
        if node["security"] == "tls":
            ob["tls"] = tls_block(node)
        tr = transport_block(node)
        if tr:
            ob["transport"] = tr
        return ob
    if p == "trojan":
        ob = {**base, "type": "trojan", "password": node["credential"], "tls": tls_block(node)}
        tr = transport_block(node)
        if tr:
            ob["transport"] = tr
        return ob
    if p == "ss":
        return {**base, "type": "shadowsocks", "method": params.get("method", ""),
                "password": node["credential"]}
    if p == "hysteria2":
        ob = {**base, "type": "hysteria2", "password": node["credential"], "tls": tls_block(node)}
        if params.get("obfs"):
            ob["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
        return ob
    if p == "tuic":
        uuid, _, pwd = node["credential"].partition(":")
        ob = {**base, "type": "tuic", "uuid": uuid, "password": pwd, "tls": tls_block(node),
              "congestion_control": params.get("congestion_control", "bbr"),
              "udp_relay_mode": params.get("udp_relay_mode", "native")}
        if params.get("alpn"):
            ob["tls"]["alpn"] = params["alpn"].split(",")
        return ob
    return None

# ---------------------------------------------------------------- SOCKS5 client (stdlib)
def socks5_connect(proxy_port, dest_host, dest_port, timeout=8.0):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[1] != 0x00:
        s.close()
        raise OSError("socks5 auth rejected")
    try:
        ip = socket.inet_aton(dest_host)
        addr = b"\x01" + ip
    except OSError:
        hb = dest_host.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb
    s.sendall(b"\x05\x01\x00" + addr + dest_port.to_bytes(2, "big"))
    resp = s.recv(10)
    if len(resp) < 2 or resp[1] != 0x00:
        s.close()
        raise OSError(f"socks5 connect rep={resp[1] if len(resp) > 1 else '?'}")
    return s

def https_probe(proxy_port, host, path, timeout=8.0):
    """GET https://host/path through the tunnel. Returns (status, ms)."""
    t0 = time.time()
    raw = socks5_connect(proxy_port, host, 443, timeout)
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ss.settimeout(timeout)
    ss.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while b"\r\n" not in data and len(data) < 4096:
        chunk = ss.recv(1024)
        if not chunk:
            break
        data += chunk
    ms = (time.time() - t0) * 1000
    ss.close()
    m = re.match(rb"HTTP/1\.[01] (\d{3})", data)
    if not m:
        raise OSError("no HTTP status line")
    return int(m.group(1)), round(ms, 1)

def udp_dns_probe(proxy_port, timeout=5.0):
    """SOCKS5 UDP ASSOCIATE + a real DNS query to 1.1.1.1. Returns ms or raises."""
    ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    ctrl.sendall(b"\x05\x01\x00")
    if ctrl.recv(2)[1] != 0x00:
        raise OSError("udp: auth rejected")
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = ctrl.recv(10)
    if len(resp) < 10 or resp[1] != 0x00:
        raise OSError("udp: associate refused")
    relay_ip = socket.inet_ntoa(resp[4:8])
    if relay_ip == "0.0.0.0":
        relay_ip = "127.0.0.1"
    relay_port = int.from_bytes(resp[8:10], "big")
    query = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x06google\x03com\x00\x00\x01\x00\x01")
    pkt = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + (53).to_bytes(2, "big") + query
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(timeout)
    t0 = time.time()
    u.sendto(pkt, (relay_ip, relay_port))
    data, _ = u.recvfrom(2048)
    ms = (time.time() - t0) * 1000
    u.close()
    ctrl.close()
    if len(data) < 20 or data[-len(query) + 2:][:2] != b"\xab\xcd" and b"\xab\xcd" not in data[:16]:
        if b"\xab\xcd" not in data:
            raise OSError("udp: bad DNS response")
    return round(ms, 1)

def speed_probe(proxy_port, nbytes=2_000_000, timeout=8.0):
    """Download nbytes from Cloudflare speed endpoint through the tunnel. Returns Mbps."""
    t0 = time.time()
    raw = socks5_connect(proxy_port, "speed.cloudflare.com", 443, timeout)
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(raw, server_hostname="speed.cloudflare.com")
    ss.settimeout(timeout)
    ss.sendall(f"GET /__down?bytes={nbytes} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n".encode())
    got, header_done = 0, False
    buf = b""
    while True:
        chunk = ss.recv(65536)
        if not chunk:
            break
        if not header_done:
            buf += chunk
            idx = buf.find(b"\r\n\r\n")
            if idx >= 0:
                header_done = True
                got += len(buf) - idx - 4
            continue
        got += len(chunk)
        if time.time() - t0 > timeout:
            break
    dt = time.time() - t0
    ss.close()
    if got < 50_000 or dt <= 0:
        raise OSError("speed: too little data")
    return round(got * 8 / dt / 1_000_000, 2)

# ---------------------------------------------------------------- core test
SERVICES = [("google", "www.google.com", "/generate_204", (204,)),
            ("facebook", "www.facebook.com", "/", (200, 301, 302)),
            ("tiktok", "www.tiktok.com", "/", (200, 301, 302, 403))]

def find_core(explicit=None):
    cands = []
    env = os.environ.get("SINGBOX")
    if env:
        cands.append(env)
    if explicit:
        cands.append(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("sing-box.exe", "sing-box"):
        cands.append(os.path.join(here, name))
        cands.append(os.path.join(os.getcwd(), name))
    import shutil
    p = shutil.which("sing-box")
    if p:
        cands.append(p)
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
        if c and os.path.isfile(c):  # Windows .exe from *nix shell etc.
            return c
    return None

def core_test(node, core, port, do_speed=False, timeout=8.0):
    ob = to_singbox_outbound(node)
    if ob is None:
        node["core"] = "skipped-unsupported"
        return node
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}],
           "outbounds": [ob, {"type": "direct", "tag": "direct"}],
           "route": {"final": "proxy"}}
    node["core"] = "fail"
    with tempfile.TemporaryDirectory() as td:
        cfgp = os.path.join(td, "cfg.json")
        with open(cfgp, "w") as f:
            json.dump(cfg, f)
        chk = subprocess.run([core, "check", "-c", cfgp], capture_output=True, timeout=20)
        if chk.returncode != 0:
            node["core_error"] = "core config check: " + chk.stderr.decode("utf-8", "replace")[:160].strip()
            return node
        proc = subprocess.Popen([core, "run", "-c", cfgp],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            up = False
            for _ in range(40):
                try:
                    s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
                    s.close()
                    up = True
                    break
                except OSError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.15)
            if not up:
                node["core_error"] = "core did not start/listen"
                return node
            results, lat = {}, []
            for name, host, path, ok_codes in SERVICES:
                try:
                    status, ms = https_probe(port, host, path, timeout)
                    results[name] = status in ok_codes
                    if results[name]:
                        lat.append(ms)
                except Exception:
                    results[name] = False
            node["services"] = results
            if lat:
                node["core"] = "ok"
                node["proxy_ms"] = round(statistics.median(lat), 1)
                try:
                    node["udp_ms"] = udp_dns_probe(port, timeout=5.0)
                    node["udp_ok"] = True
                except Exception:
                    node["udp_ok"] = False
                if do_speed:
                    try:
                        node["mbps"] = speed_probe(port)
                    except Exception:
                        node["mbps"] = 0
            else:
                node["core_error"] = "handshake ok?, no service probe passed"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except Exception:
                proc.kill()
    return node

# ---------------------------------------------------------------- sampling
def stratified_sample(nodes, limit, seed=42):
    """Sample across protocols (round-robin) so the head of one big source
    cannot crowd out whole protocols (v1 took the first N in file order,
    which produced an ss-only sample with zero vless)."""
    import random
    from collections import defaultdict
    groups = defaultdict(list)
    for n in nodes:
        groups[n["protocol"]].append(n)
    rng = random.Random(seed)
    for g in groups.values():
        rng.shuffle(g)
    out, idx = [], 0
    keys = sorted(groups)
    while len(out) < limit and any(idx < len(groups[k]) for k in keys):
        for k in keys:
            if idx < len(groups[k]) and len(out) < limit:
                out.append(groups[k][idx])
        idx += 1
    return out

# ---------------------------------------------------------------- scoring
def score_nodes(nodes):
    for n in nodes:
        if n.get("core") != "ok":
            continue
        svc = n.get("services", {})
        base = 40.0
        base += 20 * (sum(1 for v in svc.values() if v) / max(1, len(svc)))
        ms = n.get("proxy_ms", 9999)
        base += max(0.0, 25.0 - ms / 40.0)           # latency: 0 ms -> +25, 1000 ms -> +0
        n["score_general"] = round(min(100.0, base + (10 if n.get("udp_ok") else 0)), 1)
        fb = base + (15 if svc.get("facebook") else -30)
        n["score_facebook"] = round(max(0.0, min(100.0, fb)), 1)
        game = 20.0 + (45 if n.get("udp_ok") else 0) + max(0.0, 25.0 - ms / 30.0) \
            + max(0.0, 10.0 - (n.get("tcp_jitter_ms") or 99) / 5.0)
        if not n.get("udp_ok"):
            game = min(game, 30.0)
        elif ms > 800:      # v1.1: a 4-second node is NOT a gaming node, UDP or not
            game = min(game, 35.0)
        elif ms > 400:
            game = min(game, 45.0)
        n["score_game"] = round(max(0.0, min(100.0, game)), 1)
        mbps = n.get("mbps")
        vid = base
        if mbps is not None:
            vid = 30.0 + min(50.0, mbps * 5.0) + (20 if svc.get("google") else 0)
        else:
            vid = min(vid, 55.0)   # v1.1: no speed measured -> cannot claim video-good
        n["score_video"] = round(max(0.0, min(100.0, vid)), 1)

# ---------------------------------------------------------------- report
def pct(a, b):
    return f"{(100.0 * a / b):.1f}%" if b else "n/a"

def write_report(nodes, meta, outdir):
    os.makedirs(outdir, exist_ok=True)
    total_raw = meta["raw_links"]
    unique = len(nodes)                      # sampled count (gate denominators use this)
    unique_total = meta.get("unique_total", unique)
    valid = [n for n in nodes if not n["errors"]]
    invalid = [n for n in nodes if n["errors"]]
    tcp_ok = [n for n in valid if n.get("tcp_ok")]
    core_tested = [n for n in nodes if n.get("core") in ("ok", "fail")]
    core_ok = [n for n in nodes if n.get("core") == "ok"]
    # v1.1: "fast" is judged on the direct TCP-connect time to the node (~1 RTT),
    # NOT the full HTTPS-through-node time (proxy_ms), which stacks TLS + request
    # on top and made the v1 gate unreachable by construction.
    fast = [n for n in core_ok if (n.get("tcp_ms") or 99999) < 100]
    best_proxy = min((n.get("proxy_ms") or 99999 for n in core_ok), default=None)
    usable_pct = (100.0 * len(core_ok) / unique) if unique and core_tested else None

    clean = []
    for n in nodes:
        c = {k: v for k, v in n.items() if k != "params"}
        c["params"] = n["params"]
        clean.append(c)
    with open(os.path.join(outdir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "nodes": clean}, f, ensure_ascii=False, indent=1)
    cols = ["protocol", "name", "host", "port", "transport", "security", "source",
            "errors", "warnings", "tcp_ok", "tcp_ms", "core", "proxy_ms", "udp_ok",
            "mbps", "score_general", "score_facebook", "score_game", "score_video"]
    with open(os.path.join(outdir, "results.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for n in nodes:
            row = dict(n)
            row["errors"] = "; ".join(n["errors"])
            row["warnings"] = "; ".join(n["warnings"])
            w.writerow(row)
    with open(os.path.join(outdir, "working_sub.txt"), "w", encoding="utf-8") as f:
        for n in sorted(core_ok, key=lambda x: -(x.get("score_general") or 0)):
            f.write(n["raw"] + "\n")

    from collections import Counter
    err_counter = Counter(e for n in invalid for e in n["errors"])
    proto_counter = Counter(n["protocol"] for n in nodes)
    lines = []
    lines.append("# VPN Phase 0 — feasibility report\n")
    lines.append(f"- Run at: {meta['run_at']}  (from THIS machine/network: **{meta['network_note']}**)")
    lines.append(f"- Sources: {meta['sources_ok']}/{meta['sources_total']} fetched OK\n")
    lines.append("## Funnel\n")
    lines.append(f"- Raw links harvested: **{total_raw}**")
    lines.append(f"- Unique configs (after dedup): **{unique_total}** ({total_raw - unique_total} duplicates removed)")
    if unique < unique_total:
        lines.append(f"- Sampled for testing (protocol-stratified, limit {meta.get('limit')}): **{unique}** — "
                     "all rates below are of the SAMPLE")
    lines.append(f"- Format-valid: **{len(valid)}** ({pct(len(valid), unique)})")
    lines.append(f"- Format-invalid: **{len(invalid)}** ({pct(len(invalid), unique)})")
    if err_counter:
        lines.append("- Top invalid reasons:")
        for e, c in err_counter.most_common(6):
            lines.append(f"  - {c}× {e}")
    lines.append(f"- TCP reachable (of valid): **{len(tcp_ok)}** ({pct(len(tcp_ok), len(valid))})")
    if core_tested:
        lines.append(f"- Core handshake tested: **{len(core_tested)}**, passed with working services: "
                     f"**{len(core_ok)}** ({pct(len(core_ok), len(core_tested))} of tested, "
                     f"{pct(len(core_ok), unique)} of all unique)")
        lines.append(f"- Working nodes with TCP connect <100 ms (~1 RTT): **{len(fast)}**"
                     + (f" (best full-HTTPS-through-node time: {best_proxy} ms)" if best_proxy else ""))
    else:
        lines.append("- Core handshake test: **SKIPPED** (no sing-box binary found, or --no-core) — "
                     "numbers above stop at TCP level and do NOT prove a node works.")
    lines.append(f"- By protocol: " + ", ".join(f"{k}={v}" for k, v in proto_counter.most_common()))
    lines.append("\n## GATE (Phase 0 criteria, measured from this machine)\n")
    g1 = usable_pct is not None and usable_pct >= 20.0
    g2 = len(fast) >= 10
    picks = {}
    for uc, key in (("general", "score_general"), ("facebook", "score_facebook"),
                    ("game", "score_game"), ("video", "score_video")):
        ranked = sorted(core_ok, key=lambda x: -(x.get(key) or 0))[:5]
        picks[uc] = ranked
    g3 = all(len([n for n in core_ok if (n.get(k) or 0) >= 50]) >= 3
             for k in ("score_general", "score_facebook", "score_game"))
    def mark(ok):
        return "PASS" if ok else "FAIL"
    if core_tested:
        lines.append(f"- Usable rate ≥20% of unique: **{mark(g1)}**"
                     + (f" (measured {usable_pct:.1f}%)" if usable_pct is not None else ""))
    else:
        lines.append("- Usable rate ≥20%: **NOT MEASURED** (core test skipped)")
    lines.append(f"- ≥10 working nodes with TCP connect <100 ms: **{mark(g2)}** (measured {len(fast)})")
    lines.append(f"- ≥3 decent nodes per use-case (general/facebook/game): **{mark(g3)}**")
    lines.append("\n⚠️ Latency and pass rates are from THIS network. The same feed MUST be re-run "
                 "from a Myanmar connection before any public claim — the gate only counts there.\n")
    for uc, ranked in picks.items():
        if ranked:
            lines.append(f"\n## Top for {uc}\n")
            for n in ranked:
                lines.append(f"- [{n['protocol']}] {n['name'] or n['host']}:{n['port']} — "
                             f"proxy {n.get('proxy_ms')} ms, udp={'Y' if n.get('udp_ok') else 'N'}, "
                             f"mbps={n.get('mbps', '-')}, score={n.get({'general': 'score_general', 'facebook': 'score_facebook', 'game': 'score_game', 'video': 'score_video'}[uc])}")
    with open(os.path.join(outdir, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return {"unique": unique, "valid": len(valid), "tcp_ok": len(tcp_ok),
            "core_ok": len(core_ok), "fast": len(fast), "gate": (g1, g2, g3)}
