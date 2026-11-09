#!/usr/bin/env python3
"""Pull live quotes + daily history, compute ATR/DMA/RSI/stop checks/market regime,
and write an encrypted snapshot the static site decrypts with the viewer's password.

Secrets (GitHub Actions):
  DATA_KEY     base64 32-byte key that encrypts data/portfolio.enc (plaintext never committed)
  DASH_PASS    the password the owner types on the site
  FINNHUB_KEY  Finnhub API key (quotes + earnings calendar)
"""
import base64, datetime as dt, json, os, sys, time, urllib.parse, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ITER = 250_000
UA = {"User-Agent": "Mozilla/5.0 (portfolio-control)"}


# ---------- crypto ----------
def b64(b): return base64.b64encode(b).decode()
def ub64(s): return base64.b64decode(s)

def decrypt_portfolio(path, key_b64):
    blob = json.load(open(path))
    pt = AESGCM(ub64(key_b64)).decrypt(ub64(blob["iv"]), ub64(blob["ct"]), None)
    return json.loads(pt)

def encrypt_portfolio(obj, path, key_b64):
    iv = os.urandom(12)
    ct = AESGCM(ub64(key_b64)).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    json.dump({"v": 1, "iv": b64(iv), "ct": b64(ct)}, open(path, "w"))

def encrypt_for_viewer(obj, password):
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), None)
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}


# ---------- data sources ----------
def get_json(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

def finnhub_quote(sym, key):
    j = get_json(f"https://finnhub.io/api/v1/quote?symbol={urllib.parse.quote(sym)}&token={key}")
    return {"c": j["c"], "pc": j["pc"], "t": j.get("t")} if j.get("c") else None

def finnhub_earnings(key, days=21):
    today = dt.date.today()
    j = get_json(f"https://finnhub.io/api/v1/calendar/earnings?from={today}&to={today + dt.timedelta(days=days)}&token={key}")
    out = {}
    for e in j.get("earningsCalendar", []):
        out.setdefault(e["symbol"], e["date"])
    return out

def yahoo_daily(sym):
    j = get_json(f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(sym)}?range=1y&interval=1d")
    r = j["chart"]["result"][0]
    q = r["indicators"]["quote"][0]
    bars = [(h, l, c, v) for h, l, c, v in zip(q["high"], q["low"], q["close"], q["volume"]) if None not in (h, l, c)]
    meta = r.get("meta", {})
    return bars, meta


# ---------- indicators ----------
def sma(xs, n): return sum(xs[-n:]) / n if len(xs) >= n else None

def atr(bars, n=14):
    if len(bars) < n + 1: return None
    trs = [max(h - l, abs(h - bars[i - 1][2]), abs(l - bars[i - 1][2])) for i, (h, l, c, v) in enumerate(bars) if i]
    a = sum(trs[:n]) / n
    for tr in trs[n:]: a = (a * (n - 1) + tr) / n  # Wilder
    return a

def rsi(closes, n=14):
    if len(closes) < n + 1: return None
    gains = [max(0, closes[i] - closes[i - 1]) for i in range(1, len(closes))]
    losses = [max(0, closes[i - 1] - closes[i]) for i in range(1, len(closes))]
    ag, al = sum(gains[:n]) / n, sum(losses[:n]) / n
    for g, l in zip(gains[n:], losses[n:]):
        ag, al = (ag * (n - 1) + g) / n, (al * (n - 1) + l) / n
    return 100.0 if al == 0 else 100 - 100 / (1 + ag / al)

def tech(bars):
    closes = [b[2] for b in bars]
    vols = [b[3] or 0 for b in bars]
    a = atr(bars)
    s50, s200 = sma(closes, 50), sma(closes, 200)
    s50_prev = sum(closes[-60:-10]) / 50 if len(closes) >= 60 else None
    swing = min(b[1] for b in bars[-10:]) if len(bars) >= 10 else None
    v50 = sma(vols[:-1], 50)
    return {"atr": round(a, 2) if a else None, "sma50": round(s50, 2) if s50 else None,
            "sma200": round(s200, 2) if s200 else None, "rsi": round(rsi(closes), 1) if rsi(closes) else None,
            "swingLow": round(swing, 2) if swing else None, "close": closes[-1],
            "volRatio": round(vols[-1] / v50, 2) if v50 else None,
            "sma50Rising": (s50 > s50_prev) if (s50 and s50_prev) else None}


# ---------- main ----------
def main():
    data_key, pw, fkey = os.environ.get("DATA_KEY"), os.environ.get("DASH_PASS"), os.environ.get("FINNHUB_KEY", "")
    if not data_key or not pw:
        sys.exit("DATA_KEY and DASH_PASS are required")
    P = decrypt_portfolio(os.path.join(ROOT, "data", "portfolio.enc"), data_key)
    tickers = sorted({h["tk"] for h in P["holdings"] if not h.get("nolive")} | {w["tk"] for w in P["watch"]})
    errors, quotes, techs = [], {}, {}

    for s in tickers:
        if fkey:
            try:
                q = finnhub_quote(s, fkey)
                if q: quotes[s] = q
            except Exception as e:
                errors.append(f"quote {s}: {e}")
            time.sleep(1.1)  # free tier: 60/min
    # daily history once per run is cheap (Yahoo); also ESLT on TASE
    for s in tickers + ["QQQ", "SPY"]:
        try:
            bars, meta = yahoo_daily(s)
            techs[s] = tech(bars)
            if s not in quotes and meta.get("regularMarketPrice"):
                quotes[s] = {"c": meta["regularMarketPrice"], "pc": meta.get("chartPreviousClose") or meta.get("previousClose"), "src": "yahoo"}
        except Exception as e:
            errors.append(f"history {s}: {e}")
    try:
        bars, _ = yahoo_daily("ILS=X")
        P["fx"] = round(bars[-1][2], 4)
    except Exception as e:
        errors.append(f"fx: {e}")

    earnings = {}
    if fkey:
        try:
            earnings = finnhub_earnings(fkey)
        except Exception as e:
            errors.append(f"earnings: {e}")

    # market regime (O'Neil M, approximation): QQQ above a rising 50-DMA = uptrend
    qq = techs.get("QQQ", {})
    regime = P.get("market", "auto")
    if regime == "auto":
        regime = "uptrend" if (qq.get("close") and qq.get("sma50") and qq["close"] > qq["sma50"] and qq.get("sma50Rising")) else "correction"

    out = {"generated": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "portfolio": P, "quotes": quotes,
           "tech": techs, "earnings": {k: v for k, v in earnings.items() if k in tickers}, "regime": regime,
           "regimeBasis": {"qqq": qq.get("close"), "sma50": qq.get("sma50"), "rising": qq.get("sma50Rising")},
           "errors": errors[:20]}
    os.makedirs(os.path.join(ROOT, "site"), exist_ok=True)
    json.dump(encrypt_for_viewer(out, pw), open(os.path.join(ROOT, "site", "data.enc.json"), "w"))
    print(f"ok: {len(quotes)} quotes, {len(techs)} histories, regime={regime}, errors={len(errors)}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "encrypt":  # encrypt data/portfolio.json -> data/portfolio.enc
        encrypt_portfolio(json.load(open(sys.argv[2])), os.path.join(ROOT, "data", "portfolio.enc"), os.environ["DATA_KEY"])
        print("portfolio.enc written")
    else:
        main()
