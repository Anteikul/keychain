#!/usr/bin/env python3
import base64, hashlib, hmac, html, json, os, secrets, sqlite3, struct, time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("KEYCHAIN_DB", os.path.join(ROOT, "keychain.db"))
KEY_PATH = os.environ.get("KEYCHAIN_KEY", os.path.join(ROOT, ".device-key"))
HOST = os.environ.get("KEYCHAIN_HOST", "0.0.0.0")
PORT = int(os.environ.get("KEYCHAIN_PORT", "80"))
SESSION_AGE = 15 * 60
MAX_BODY = 1024 * 1024
attempts = {}

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init():
    os.makedirs(ROOT, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, secrets.token_bytes(32)); os.close(fd)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, passhash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, login TEXT NOT NULL DEFAULT '', secret BLOB NOT NULL, url TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'password', shared INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS icons(id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE NOT NULL, mime TEXT NOT NULL, data BLOB NOT NULL, created_by INTEGER REFERENCES users(id) ON DELETE SET NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT UNIQUE NOT NULL, ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, last_activity INTEGER NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS item_versions(id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE, changed_by INTEGER REFERENCES users(id) ON DELETE SET NULL, login TEXT NOT NULL DEFAULT '', secret BLOB NOT NULL, totp_secret BLOB, created INTEGER NOT NULL);
        """)
        cols={r[1] for r in c.execute("PRAGMA table_info(items)")}
        if "totp_secret" not in cols: c.execute("ALTER TABLE items ADD COLUMN totp_secret BLOB")
        if "deleted_at" not in cols: c.execute("ALTER TABLE items ADD COLUMN deleted_at INTEGER")
        if "deleted_by" not in cols: c.execute("ALTER TABLE items ADD COLUMN deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL")
        if "icon_id" not in cols: c.execute("ALTER TABLE items ADD COLUMN icon_id INTEGER REFERENCES icons(id) ON DELETE SET NULL")
        if "folder" not in cols: c.execute("ALTER TABLE items ADD COLUMN folder TEXT NOT NULL DEFAULT ''")
        if "tags" not in cols: c.execute("ALTER TABLE items ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
        usercols={r[1] for r in c.execute("PRAGMA table_info(users)")}
        if "active" not in usercols: c.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")

def audit(c, user, action, target="", detail="", ip=""):
    c.execute("INSERT INTO audit(user_id,username,action,target,detail,ip,created) VALUES(?,?,?,?,?,?,?)",(user["id"] if user else None,user["username"] if user else "system",action,target,detail,ip,int(time.time())))

def key(): return open(KEY_PATH, "rb").read()
def enc(value):
    nonce=secrets.token_bytes(12); return nonce + AESGCM(key()).encrypt(nonce, value.encode(), b"keychain-v1")
def dec(value): return AESGCM(key()).decrypt(value[:12], value[12:], b"keychain-v1").decode()
def pw_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$"+base64.urlsafe_b64encode(salt).decode()+"$"+base64.urlsafe_b64encode(digest).decode()
def pw_ok(password, stored):
    try:
        _,s,d=stored.split("$"); got=pw_hash(password,base64.urlsafe_b64decode(s)).split("$")[2]
        return hmac.compare_digest(got,d)
    except Exception: return False
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64(s): return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
def token_hash(token):return hashlib.sha256(token.encode()).hexdigest()
def session(uid,ip="",user_agent=""):
    token=b64(secrets.token_bytes(32)); now=int(time.time())
    with db() as c:
        c.execute("DELETE FROM sessions WHERE expires<? OR revoked=1",(now-86400,))
        c.execute("INSERT INTO sessions(user_id,token_hash,ip,user_agent,created,last_activity,expires) VALUES(?,?,?,?,?,?,?)",(uid,token_hash(token),ip,user_agent[:500],now,now,now+SESSION_AGE))
    return token
def session_uid(token):
    if not token:return None
    with db() as c:
        r=c.execute("SELECT user_id FROM sessions WHERE token_hash=? AND revoked=0 AND expires>?",(token_hash(token),int(time.time()))).fetchone()
        return r["user_id"] if r else None
def session_expiry(token):
    if not token:return 0
    with db() as c:
        r=c.execute("SELECT expires FROM sessions WHERE token_hash=? AND revoked=0",(token_hash(token),)).fetchone(); return r["expires"] if r else 0
def csrf_token(uid):return b64(hmac.new(key(),f"csrf:{uid}".encode(),hashlib.sha256).digest())
def totp(secret):
    clean="".join(secret.upper().split()).replace("-","")
    raw=base64.b32decode(clean+"="*((8-len(clean)%8)%8),casefold=True)
    counter=int(time.time())//30
    digest=hmac.new(raw,struct.pack(">Q",counter),hashlib.sha1).digest(); off=digest[-1]&15
    return str((struct.unpack(">I",digest[off:off+4])[0]&0x7fffffff)%1000000).zfill(6),30-int(time.time())%30

def esc(v): return html.escape(str(v or ""), quote=True)
def image_type(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):return "image/png"
    if data.startswith(b"\xff\xd8\xff"):return "image/jpeg"
    if data.startswith((b"GIF87a",b"GIF89a")):return "image/gif"
    if len(data)>12 and data[:4]==b"RIFF" and data[8:12]==b"WEBP":return "image/webp"
    return None
def layout(title, body, user=None, csrf="", expires=0):
    adminlinks='<details class=admin-menu><summary>Administrace</summary><div class=admin-dropdown><a href=/users>Uživatelé</a><a href=/trash>Koš</a><a href=/logs>Auditní log</a></div></details>' if user and user["is_admin"] else ''
    timer='<span class=session-timer>Odhlášení za <strong data-session-timer>--:--</strong></span>' if user else ''
    nav = f'<nav><a class="brand" href="/vault"><span>⌁</span> Klíčenka</a><div class="navright"><a href=/vault>Hesla</a><a href=/sessions>Relace</a>{timer}{adminlinks}<button class="ghost theme" type=button data-theme-toggle title="Světlý/tmavý režim">◐</button><a href=/account>{esc(user["username"])}</a><form method=post action=/logout><input type=hidden name=csrf value="{csrf}"><button class=ghost>Odhlásit</button></form></div></nav>' if user else '<button class="theme floating ghost" type=button data-theme-toggle title="Světlý/tmavý režim">◐</button>'
    return f'''<!doctype html><html lang=cs><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>{esc(title)} · Klíčenka</title><link rel=icon href=/favicon.svg type=image/svg+xml><link rel=stylesheet href=/static.css></head><body data-session-expires="{expires}" data-user-key="{user['id'] if user else ''}">{nav}<main>{body}</main><script src=/app.js defer></script></body></html>'''

class App(BaseHTTPRequestHandler):
    server_version="Keychain"
    def log_message(self, fmt, *args): print(time.strftime("%F %T"), self.client_address[0], fmt%args)
    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data=body.encode(); self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Content-Length",str(len(data)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","no-referrer"); self.send_header("Content-Security-Policy","default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'")
        for k,v in (headers or []): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)
    def redirect(self,path,headers=None): self.send_response(303); self.send_header("Location",path); [self.send_header(k,v) for k,v in (headers or [])]; self.end_headers()
    def form(self):
        n=int(self.headers.get("Content-Length","0"));
        if n>MAX_BODY: raise ValueError("too large")
        return {k:v[-1] for k,v in parse_qs(self.rfile.read(n).decode(),keep_blank_values=True).items()}
    def auth(self):
        jar=cookies.SimpleCookie(self.headers.get("Cookie","")); token=jar.get("kc_session"); uid=session_uid(token.value) if token else None
        if not uid:return None
        with db() as c:return c.execute("SELECT * FROM users WHERE id=? AND active=1",(uid,)).fetchone()
    def csrf(self):
        jar=cookies.SimpleCookie(self.headers.get("Cookie","")); return jar.get("kc_csrf").value if jar.get("kc_csrf") else ""
    def session_token(self):
        jar=cookies.SimpleCookie(self.headers.get("Cookie","")); token=jar.get("kc_session"); return token.value if token else ""
    def expiry(self):
        jar=cookies.SimpleCookie(self.headers.get("Cookie","")); token=jar.get("kc_session")
        return session_expiry(token.value) if token else 0
    def require_post(self,f):
        user=self.auth()
        if not user:self.redirect("/"); return None,None
        expected=csrf_token(user["id"])
        if not hmac.compare_digest(expected,f.get("csrf","")):self.send(403,"Neplatný požadavek"); return None,None
        return user,f
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/static.css": return self.send(200,open(os.path.join(ROOT,"static.css")).read(),"text/css")
        if path=="/app.js": return self.send(200,open(os.path.join(ROOT,"app.js")).read(),"text/javascript")
        if path in ("/favicon.svg","/favicon.ico","/apple-touch-icon.png","/apple-touch-icon-precomposed.png"): return self.send(200,open(os.path.join(ROOT,"favicon.svg")).read(),"image/svg+xml")
        if path=="/icon":
            icon_id=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            with db() as c:r=c.execute("SELECT mime,data FROM icons WHERE id=?",(icon_id,)).fetchone()
            if not r:return self.send(404,"Nenalezeno")
            data=bytes(r["data"]); self.send_response(200); self.send_header("Content-Type",r["mime"]); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","public, max-age=31536000, immutable"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); return self.wfile.write(data)
        user=self.auth()
        if path=="/":
            if user:return self.redirect("/vault")
            with db() as c: first=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0
            label="Založit správce" if first else "Přihlásit se"; sub="Vytvořte první účet správce." if first else "Vaše hesla zůstávají na tomto zařízení."
            body=f'''<section class=login><div class=mark>⌁</div><h1>Klíčenka</h1><p>{sub}</p><form method=post action={'/setup' if first else '/login'}><label>Uživatelské jméno<input name=username required autocomplete=username autofocus></label><label>Heslo<input type=password name=password required minlength=8 autocomplete={'new-password' if first else 'current-password'}></label><button>{label}</button></form></section>'''
            return self.send(200,layout("Přihlášení",body))
        if not user:return self.redirect("/")
        csrf=csrf_token(user["id"])
        if path=="/vault":
            with db() as c:
                rows=c.execute("SELECT items.*,users.username owner FROM items JOIN users ON users.id=items.owner_id WHERE deleted_at IS NULL AND (owner_id=? OR shared=1) ORDER BY shared DESC,updated DESC",(user["id"],)).fetchall()
                icons=c.execute("SELECT id FROM icons ORDER BY created DESC").fetchall()
                folders=sorted({r["folder"] for r in rows if r["folder"]})
            cards="".join(self.card(r,csrf,user) for r in rows) or '<div class=empty><div>◇</div><h3>Trezor je prázdný</h3><p>Přidejte první heslo nebo TOTP.</p></div>'
            folder_options='<option value="">Všechny složky</option>'+''.join(f'<option value="{esc(x)}">{esc(x)}</option>' for x in folders)
            body=f'''<header class=pagehead><div><p class=eyebrow>ZAŠIFROVANÝ TREZOR</p><h1>Vaše přístupy</h1></div><button data-open=add>＋ Přidat položku</button></header><div class=filters><button class=chip active data-filter=all>Vše</button><button class=chip data-filter=mine>Moje</button><button class=chip data-filter=shared>Sdílené</button><select id=folder-filter aria-label="Filtrovat složku">{folder_options}</select><div class=view-switch><button class="chip active" data-view=grid title="Karty">▦ Karty</button><button class=chip data-view=list title="Seznam">☷ Seznam</button></div><input id=search placeholder="Hledat…"></div><section class=grid data-vault>{cards}</section>{self.item_dialog(csrf,icons,folders)}{self.delete_dialog(csrf)}'''
            return self.send(200,layout("Trezor",body,user,csrf,self.expiry()))
        if path=="/users" and user["is_admin"]:
            with db() as c:
                users=c.execute("SELECT id,username,is_admin,active,created FROM users ORDER BY active DESC,username").fetchall()
                first_admin=c.execute("SELECT MIN(id) FROM users WHERE is_admin=1").fetchone()[0]
            lines=""
            for x in users:
                protected=x["id"] in (user["id"],first_admin)
                account_action=""
                if not protected:
                    if x["active"]:account_action=f'''<form method=post action=/remove-user onsubmit="return confirm('Odebrat uživatele {esc(x['username'])}?')"><input type=hidden name=csrf value="{csrf}"><input type=hidden name=user_id value={x["id"]}><button class="ghost danger-text">Odstranit</button></form>'''
                    else:account_action=f'''<form method=post action=/restore-user><input type=hidden name=csrf value="{csrf}"><input type=hidden name=user_id value={x["id"]}><button class=ghost>Obnovit účet</button></form>'''
                reset=f'''<form class=resetform method=post action=/reset-password><input type=hidden name=csrf value="{csrf}"><input type=hidden name=user_id value={x["id"]}><input type=password name=password minlength=8 placeholder="Nové heslo" required><button class=ghost>Změnit heslo</button></form>''' if x["active"] else ""
                lines+=f'''<tr class={'inactive' if not x['active'] else ''}><td>{esc(x["username"])}</td><td>{"Správce" if x["is_admin"] else "Uživatel"}</td><td><span class="status {'on' if x['active'] else 'off'}">{'Aktivní' if x['active'] else 'Odebraný'}</span></td><td>{time.strftime("%d. %m. %Y",time.localtime(x["created"]))}</td><td>{reset}</td><td>{account_action}</td></tr>'''
            body=f'''<header class=pagehead><div><p class=eyebrow>SPRÁVA</p><h1>Uživatelé</h1></div></header><div class=panel><h2>Přidat uživatele</h2><form class=inlineform method=post action=/users><input type=hidden name=csrf value="{csrf}"><input name=username placeholder="Nové uživatelské jméno" required><input type=password name=password minlength=8 placeholder="Dočasné heslo (min. 8)" required><button>Přidat</button></form><div class=tablewrap><table><thead><tr><th>Jméno</th><th>Role</th><th>Stav</th><th>Vytvořen</th><th>Změna hesla</th><th>Účet</th></tr></thead><tbody>{lines}</tbody></table></div></div>'''
            return self.send(200,layout("Uživatelé",body,user,csrf,self.expiry()))
        if path=="/account":
            body=f'''<header class=pagehead><div><p class=eyebrow>NASTAVENÍ</p><h1>Můj účet</h1></div></header><div class="panel account-panel"><h2>Změnit heslo</h2><p>Po změně používejte nové heslo při příštím přihlášení.</p><form method=post action=/change-password><input type=hidden name=csrf value="{csrf}"><label>Současné heslo<input type=password name=current_password autocomplete=current-password required></label><label>Nové heslo<input type=password name=new_password minlength=8 autocomplete=new-password required></label><label>Nové heslo znovu<input type=password name=confirm_password minlength=8 autocomplete=new-password required></label><button>Změnit moje heslo</button></form></div>'''
            return self.send(200,layout("Můj účet",body,user,csrf,self.expiry()))
        if path=="/sessions":
            now=int(time.time()); current_hash=token_hash(self.session_token())
            with db() as c:
                if user["is_admin"]:rows=c.execute("SELECT sessions.*,users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE revoked=0 AND expires>? ORDER BY last_activity DESC",(now,)).fetchall()
                else:rows=c.execute("SELECT sessions.*,users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE user_id=? AND revoked=0 AND expires>? ORDER BY last_activity DESC",(user["id"],now)).fetchall()
            lines=""
            for s in rows:
                current=s["token_hash"]==current_hash
                ua=esc((s["user_agent"] or "Neznámé zařízení")[:100])
                lines+=f'''<tr><td>{esc(s["username"])}</td><td>{ua}{' <span class="status on">Tato relace</span>' if current else ''}</td><td>{esc(s["ip"])}</td><td>{time.strftime("%d. %m. %Y %H:%M",time.localtime(s["last_activity"]))}</td><td><form method=post action=/revoke-session><input type=hidden name=csrf value="{csrf}"><input type=hidden name=session_id value="{s['id']}"><button class="ghost danger-text">Ukončit</button></form></td></tr>'''
            body=f'''<header class=pagehead><div><p class=eyebrow>BEZPEČNOST</p><h1>Aktivní relace</h1><p>Zde můžete okamžitě odhlásit zařízení. Relace bez aktivity automaticky končí po 15 minutách.</p></div></header><div class="panel tablewrap"><table><thead><tr><th>Uživatel</th><th>Zařízení</th><th>IP adresa</th><th>Aktivita</th><th>Akce</th></tr></thead><tbody>{lines or '<tr><td colspan=5>Žádné aktivní relace</td></tr>'}</tbody></table></div>'''
            return self.send(200,layout("Aktivní relace",body,user,csrf,self.expiry()))
        if path=="/history":
            item_id=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            with db() as c:
                item=c.execute("SELECT * FROM items WHERE id=? AND deleted_at IS NULL",(item_id,)).fetchone()
                if not item or (item["owner_id"]!=user["id"] and not user["is_admin"]):return self.send(403,"Historie není dostupná")
                versions=c.execute("SELECT item_versions.*,users.username changer FROM item_versions LEFT JOIN users ON users.id=item_versions.changed_by WHERE item_id=? ORDER BY created DESC",(item_id,)).fetchall()
            cards=""
            for v in versions:
                try:old_secret=dec(v["secret"])
                except Exception:old_secret="[nelze dešifrovat]"
                cards+=f'''<article class="card version-card"><h2>{time.strftime("%d. %m. %Y %H:%M",time.localtime(v["created"]))}</h2><p>Změnil: {esc(v["changer"] or 'neznámý uživatel')}</p><div class=credential><span>{esc(v["login"] or '—')}</span><button class=ghost data-copy-value="{esc(v['login'])}">Kopírovat jméno</button></div><div class=secret><code data-secret="{esc(old_secret)}">••••••••••</code><button class=ghost data-reveal>Zobrazit</button><button class=ghost data-copy-value="{esc(old_secret)}">Kopírovat heslo</button></div><form method=post action=/restore-version><input type=hidden name=csrf value="{csrf}"><input type=hidden name=version_id value="{v['id']}"><button>Obnovit tuto verzi</button></form></article>'''
            if not cards:cards='<div class=empty><div>↶</div><h3>Zatím bez historie</h3><p>Historie vznikne při změně uživatelského jména, hesla nebo TOTP.</p></div>'
            body=f'''<header class=pagehead><div><p class=eyebrow>HISTORIE ZMĚN</p><h1>{esc(item['title'])}</h1></div><a class=button href=/vault>Zpět k heslům</a></header><section class=grid>{cards}</section>'''
            return self.send(200,layout("Historie",body,user,csrf,self.expiry()))
        if path=="/logs" and user["is_admin"]:
            with db() as c: logs=c.execute("SELECT * FROM audit ORDER BY created DESC LIMIT 500").fetchall()
            lines="".join(f'<tr><td>{time.strftime("%d. %m. %Y %H:%M:%S",time.localtime(x["created"]))}</td><td>{esc(x["username"])}</td><td>{esc(x["action"])}</td><td>{esc(x["target"])}</td><td>{esc(x["detail"])}</td><td>{esc(x["ip"])}</td></tr>' for x in logs)
            body=f'''<header class=pagehead><div><p class=eyebrow>BEZPEČNOST</p><h1>Auditní log</h1></div></header><div class="panel tablewrap"><table><thead><tr><th>Čas</th><th>Uživatel</th><th>Akce</th><th>Cíl</th><th>Detail</th><th>IP</th></tr></thead><tbody>{lines}</tbody></table></div>'''
            return self.send(200,layout("Auditní log",body,user,csrf,self.expiry()))
        if path=="/trash" and user["is_admin"]:
            with db() as c: rows=c.execute("SELECT items.*,users.username owner,deleter.username deleter FROM items JOIN users ON users.id=items.owner_id LEFT JOIN users deleter ON deleter.id=items.deleted_by WHERE items.deleted_at IS NOT NULL ORDER BY items.deleted_at DESC").fetchall()
            cards="".join(f'''<article class="card trash-card"><div class=cardtop><span class=type>↶</span><span class=badge>{'Sdílené' if r['shared'] else 'Soukromé'}</span></div><h2>{esc(r['title'])}</h2><p>Vlastník: {esc(r['owner'])}</p><small>Smazal {esc(r['deleter'] or 'neznámý uživatel')} · {time.strftime('%d. %m. %Y %H:%M',time.localtime(r['deleted_at']))}</small><form method=post action=/restore><input type=hidden name=csrf value="{csrf}"><input type=hidden name=id value="{r['id']}"><button>Obnovit položku</button></form></article>''' for r in rows) or '<div class=empty><div>✓</div><h3>Koš je prázdný</h3><p>Nejsou zde žádné položky k obnovení.</p></div>'
            body=f'''<header class=pagehead><div><p class=eyebrow>SPRÁVA</p><h1>Koš</h1><p>Smazané položky jsou stále zašifrované a viditelné pouze administrátorovi.</p></div></header><section class=grid>{cards}</section>'''
            return self.send(200,layout("Koš",body,user,csrf,self.expiry()))
        if path=="/totp":
            item_id=parse_qs(urlparse(self.path).query).get("id",[""])[0]
            with db() as c:r=c.execute("SELECT * FROM items WHERE id=? AND deleted_at IS NULL AND (owner_id=? OR shared=1)",(item_id,user["id"])).fetchone()
            if not r or (not r["totp_secret"] and r["kind"]!="totp"):return self.send(404,json.dumps({"error":"Nenalezeno"}),"application/json")
            try:code,left=totp(dec(r["totp_secret"] or r["secret"]))
            except Exception:return self.send(400,json.dumps({"error":"Neplatné TOTP"}),"application/json")
            return self.send(200,json.dumps({"code":code,"left":left}),"application/json")
        if path=="/heartbeat":
            expires=int(time.time())+SESSION_AGE
            token=self.session_token()
            with db() as c:c.execute("UPDATE sessions SET last_activity=?,expires=? WHERE token_hash=? AND revoked=0",(int(time.time()),expires,token_hash(token)))
            return self.send(200,json.dumps({"expires":expires,"csrf":csrf_token(user["id"])}),"application/json",[("Set-Cookie",f"kc_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_AGE}")])
        self.send(404,"Nenalezeno")
    def card(self,r,csrf,user):
        try: secret=dec(r["secret"])
        except Exception: secret="[nelze dešifrovat]"
        try: totp_raw=dec(r["totp_secret"]) if r["totp_secret"] else (secret if r["kind"]=="totp" else "")
        except Exception: totp_raw=""
        code,left=(totp(totp_raw) if totp_raw else ("",0)); meta=esc(r["url"] or "Přihlašovací údaje")
        delete=f'''<button class="icon delete" type=button title=Smazat data-delete-id="{r['id']}" data-delete-title="{esc(r['title'])}">×</button>''' if r["owner_id"]==user["id"] or user["is_admin"] else ""
        editable=r["owner_id"]==user["id"] or user["is_admin"]
        editdata=esc(json.dumps({"id":r["id"],"title":r["title"],"login":r["login"],"secret":secret,"totp":totp_raw,"url":r["url"],"notes":r["notes"],"shared":bool(r["shared"]),"icon_id":r["icon_id"] or "","folder":r["folder"],"tags":r["tags"]},ensure_ascii=False))
        loginrow=f'''<div class=credential><span>{esc(r["login"])}</span><button class=ghost data-copy-value="{esc(r['login'])}">Kopírovat jméno</button></div>''' if r["login"] else ""
        totprow=f'''<div class="credential totp" data-totp-id="{r['id']}" data-left="{left}"><div class=totp-ring style="--progress:{left/30*360:.0f}deg;--duration:{left}s"><span data-totp-left>{left}</span></div><div class=totp-value><code data-totp-code>{code}</code><small>platnost kódu</small></div><button class=ghost data-copy-totp>Kopírovat TOTP</button></div>''' if totp_raw else ""
        edit=f'<button class="icon edit" title="Upravit" data-edit="{editdata}">✎</button>' if editable else ""
        history=f'<a class="icon history" title="Historie" href="/history?id={r["id"]}">↶</a>' if editable else ""
        actions=f'<div class=list-actions>{history}{edit}{delete}</div>'
        taxonomy=(f'<span class=folder-badge>▰ {esc(r["folder"])}</span>' if r["folder"] else '')+''.join(f'<span class=tag>#{esc(t.strip())}</span>' for t in r["tags"].split(",") if t.strip())
        icon=f'<img src="/icon?id={r["icon_id"]}" alt="">' if r["icon_id"] else '⌘'
        return f'''<article class=card data-scope={'shared' if r['shared'] else 'mine'} data-folder="{esc(r['folder'].lower())}" data-search="{esc((r['title']+' '+r['login']+' '+r['url']+' '+r['folder']+' '+r['tags']).lower())}"><div class=cardtop><span class=type>{icon}</span><span class=badge>{'Sdílené' if r['shared'] else 'Soukromé'}</span><span class=card-actions>{history}{edit}{delete}</span></div><h2>{esc(r['title'])}</h2><p>{meta}</p><div class=taxonomy>{taxonomy}</div>{loginrow}<div class=secret><code data-secret="{esc(secret)}">{'•'*10}</code><button class=ghost data-reveal>Zobrazit</button><button class=ghost data-copy-value="{esc(secret)}">Kopírovat heslo</button></div>{totprow}{f'<small>Sdílí {esc(r["owner"])}</small>' if r['shared'] else ''}{actions}</article>'''
    def item_dialog(self,csrf,icons,folders):
        choices='<button type=button class="icon-choice selected" data-icon-id=""><span>⌘</span></button>'+''.join(f'<button type=button class=icon-choice data-icon-id="{x["id"]}"><img src="/icon?id={x["id"]}" alt=""></button>' for x in icons)
        folder_list=''.join(f'<option value="{esc(x)}">' for x in folders)
        return f'''<dialog id=add><form method=post action=/item><div class=dialoghead><div><p class=eyebrow>POLOŽKA TREZORU</p><h2 data-dialog-title>Přidat přístup</h2></div><button type=button class=close data-close>×</button></div><input type=hidden name=csrf value="{csrf}"><input type=hidden name=id><input type=hidden name=icon_id><input type=hidden name=icon_data><label>Ikona <span class=optional>(společná knihovna)</span><div class=icon-picker><label class=icon-upload title="Nahrát novou ikonu">＋<input type=file accept="image/png,image/jpeg,image/gif,image/webp" data-icon-file></label><button type=button class="icon-choice upload-preview" data-upload-preview hidden><img alt="Náhled nové ikony"></button>{choices}</div><small>PNG, JPG, GIF nebo WebP, maximálně 256 kB</small></label><label>Název<input name=title required placeholder="Např. Firemní e-mail"></label><div class=field-row><label>Složka<input name=folder list=folders placeholder="Např. Servery"><datalist id=folders>{folder_list}</datalist></label><label>Štítky<input name=tags placeholder="proxmox, produkce"></label></div><label>Uživatelské jméno<input name=login autocomplete=off></label><label>Heslo<div class=password-field><input name=secret required autocomplete=off><button type=button class=ghost data-generate-password>Generovat</button></div><span class=generator-options><label>Délka <input type=number min=12 max=64 value=20 data-password-length></label><label class=check><input type=checkbox checked data-password-symbols> Symboly</label></span></label><label>TOTP secret <span class=optional>(volitelné, Base32)</span><input name=totp_secret autocomplete=off placeholder="JBSWY3DPEHPK3PXP"></label><label>Webová adresa<input name=url type=url></label><label>Poznámka<textarea name=notes></textarea></label><label class=check><input type=checkbox name=shared value=1><span>Sdílet se všemi uživateli</span></label><button data-save>Uložit zašifrovaně</button></form></dialog>'''
    def delete_dialog(self,csrf):
        return f'''<dialog id=delete-confirm><form method=post action=/delete><div class=dialoghead><div><p class="eyebrow danger-text">NEVRATNÁ AKCE</p><h2>Smazat položku?</h2></div><button type=button class=close data-delete-close>×</button></div><p>Položka <strong data-delete-name></strong> bude trvale odstraněna. Pro potvrzení opište její název:</p><input type=hidden name=csrf value="{csrf}"><input type=hidden name=id><label>Název položky<input name=confirmation required autocomplete=off data-delete-input></label><div class=dialog-actions><button type=button class=ghost data-delete-close>Zrušit</button><button class=danger data-delete-submit disabled>Smazat natrvalo</button></div></form></dialog>'''
    def do_POST(self):
        try:f=self.form()
        except Exception:return self.send(413,"Příliš velký požadavek")
        path=urlparse(self.path).path
        if path=="/setup":
            with db() as c:
                if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]: return self.send(403,"Nastavení již proběhlo")
                if len(f.get("password",""))<8:return self.send(400,"Heslo musí mít alespoň 8 znaků")
                c.execute("INSERT INTO users(username,passhash,is_admin,created) VALUES(?,?,1,?)",(f.get("username",""),pw_hash(f["password"]),int(time.time())))
                u=c.execute("SELECT * FROM users WHERE id=last_insert_rowid()").fetchone(); audit(c,u,"Založení administrátora",u["username"],ip=self.client_address[0])
            return self.redirect("/")
        if path=="/login":
            ip=self.client_address[0]; recent=[x for x in attempts.get(ip,[]) if x>time.time()-600]; attempts[ip]=recent
            if len(recent)>=8:return self.send(429,layout("Počkejte","<section class=login><h1>Příliš mnoho pokusů</h1><p>Zkuste to za 10 minut.</p></section>"))
            with db() as c:u=c.execute("SELECT * FROM users WHERE username=? AND active=1",(f.get("username",""),)).fetchone()
            if not u or not pw_ok(f.get("password",""),u["passhash"]): recent.append(time.time()); time.sleep(.4); return self.send(401,layout("Přihlášení","<section class=login><h1>Přihlášení se nezdařilo</h1><p>Nesprávné jméno nebo heslo.</p><a href=/ class=button>Zkusit znovu</a></section>"))
            with db() as c: audit(c,u,"Přihlášení",ip=self.client_address[0])
            attempts.pop(ip,None); csrf=b64(secrets.token_bytes(24)); token=session(u["id"],ip,self.headers.get("User-Agent","")); hdr=[("Set-Cookie",f"kc_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_AGE}"),("Set-Cookie",f"kc_csrf={csrf}; SameSite=Strict; Path=/; Max-Age={SESSION_AGE}")]
            return self.redirect("/vault",hdr)
        user,f=self.require_post(f)
        if not user:return
        if path=="/logout":
            with db() as c:c.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?",(token_hash(self.session_token()),))
            return self.redirect("/",[("Set-Cookie","kc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),("Set-Cookie","kc_csrf=; SameSite=Strict; Path=/; Max-Age=0")])
        if path=="/item":
            if not f.get("title") or not f.get("secret"):return self.send(400,"Chybí název nebo tajemství")
            if f.get("totp_secret"):
                try:totp(f["totp_secret"])
                except Exception:return self.send(400,"TOTP secret není platný Base32 řetězec")
            now=int(time.time())
            with db() as c:
                folder=f.get("folder","").strip()[:100]
                tags=",".join(dict.fromkeys(x.strip() for x in f.get("tags","").split(",") if x.strip()))[:500]
                icon_id=f.get("icon_id") or None
                if f.get("icon_data"):
                    try:raw=base64.b64decode(f["icon_data"],validate=True)
                    except Exception:return self.send(400,"Ikonu se nepodařilo načíst")
                    mime=image_type(raw)
                    if not mime or len(raw)>256*1024:return self.send(400,"Ikona musí být PNG, JPG, GIF nebo WebP a mít nejvýše 256 kB")
                    digest=hashlib.sha256(raw).hexdigest()
                    c.execute("INSERT OR IGNORE INTO icons(sha256,mime,data,created_by,created) VALUES(?,?,?,?,?)",(digest,mime,raw,user["id"],now))
                    icon_id=c.execute("SELECT id FROM icons WHERE sha256=?",(digest,)).fetchone()["id"]
                    audit(c,user,"Nahrání ikony",digest[:12],ip=self.client_address[0])
                elif icon_id and not c.execute("SELECT 1 FROM icons WHERE id=?",(icon_id,)).fetchone():return self.send(400,"Vybraná ikona neexistuje")
                item_id=f.get("id")
                if item_id:
                    old=c.execute("SELECT * FROM items WHERE id=? AND deleted_at IS NULL",(item_id,)).fetchone()
                    if not old or not (old["owner_id"]==user["id"] or user["is_admin"]): return self.send(403,"Nemáte oprávnění položku upravit")
                    old_secret=dec(old["secret"]); old_totp=dec(old["totp_secret"]) if old["totp_secret"] else ""
                    if old_secret!=f["secret"] or old["login"]!=f.get("login","") or old_totp!=f.get("totp_secret",""):
                        c.execute("INSERT INTO item_versions(item_id,changed_by,login,secret,totp_secret,created) VALUES(?,?,?,?,?,?)",(item_id,user["id"],old["login"],old["secret"],old["totp_secret"],now))
                    c.execute("UPDATE items SET title=?,folder=?,tags=?,login=?,secret=?,totp_secret=?,url=?,notes=?,kind='password',shared=?,icon_id=?,updated=? WHERE id=?",(f["title"][:200],folder,tags,f.get("login","")[:300],enc(f["secret"]),enc(f["totp_secret"]) if f.get("totp_secret") else None,f.get("url","")[:1000],f.get("notes","")[:4000],1 if f.get("shared")=="1" else 0,icon_id,now,item_id))
                    audit(c,user,"Úprava položky",f["title"][:200],"Upraveny přihlašovací údaje",self.client_address[0])
                else:
                    c.execute("INSERT INTO items(owner_id,title,folder,tags,login,secret,totp_secret,url,notes,kind,shared,icon_id,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(user["id"],f["title"][:200],folder,tags,f.get("login","")[:300],enc(f["secret"]),enc(f["totp_secret"]) if f.get("totp_secret") else None,f.get("url","")[:1000],f.get("notes","")[:4000],"password",1 if f.get("shared")=="1" else 0,icon_id,now,now))
                    audit(c,user,"Vytvoření položky",f["title"][:200],"Sdílená" if f.get("shared")=="1" else "Soukromá",self.client_address[0])
            return self.redirect("/vault")
        if path=="/delete":
            with db() as c:
                r=c.execute("SELECT owner_id,title FROM items WHERE id=? AND deleted_at IS NULL",(f.get("id"),)).fetchone()
                if r and (r["owner_id"]==user["id"] or user["is_admin"]):
                    if not hmac.compare_digest(f.get("confirmation",""),r["title"]):return self.send(400,"Název položky nesouhlasí. Položka nebyla smazána.")
                    c.execute("UPDATE items SET deleted_at=?,deleted_by=?,updated=? WHERE id=?",(int(time.time()),user["id"],int(time.time()),f["id"])); audit(c,user,"Přesunutí položky do koše",r["title"],ip=self.client_address[0])
            return self.redirect("/vault")
        if path=="/restore" and user["is_admin"]:
            with db() as c:
                r=c.execute("SELECT title FROM items WHERE id=? AND deleted_at IS NOT NULL",(f.get("id"),)).fetchone()
                if not r:return self.send(404,"Položka v koši neexistuje")
                c.execute("UPDATE items SET deleted_at=NULL,deleted_by=NULL,updated=? WHERE id=?",(int(time.time()),f["id"])); audit(c,user,"Obnovení položky z koše",r["title"],ip=self.client_address[0])
            return self.redirect("/trash")
        if path=="/restore-version":
            now=int(time.time())
            with db() as c:
                v=c.execute("SELECT item_versions.*,items.owner_id,items.title,items.login current_login,items.secret current_secret,items.totp_secret current_totp FROM item_versions JOIN items ON items.id=item_versions.item_id WHERE item_versions.id=? AND items.deleted_at IS NULL",(f.get("version_id"),)).fetchone()
                if not v:return self.send(404,"Historická verze neexistuje")
                if v["owner_id"]!=user["id"] and not user["is_admin"]:return self.send(403,"Verzi nelze obnovit")
                c.execute("INSERT INTO item_versions(item_id,changed_by,login,secret,totp_secret,created) VALUES(?,?,?,?,?,?)",(v["item_id"],user["id"],v["current_login"],v["current_secret"],v["current_totp"],now))
                c.execute("UPDATE items SET login=?,secret=?,totp_secret=?,updated=? WHERE id=?",(v["login"],v["secret"],v["totp_secret"],now,v["item_id"])); audit(c,user,"Obnovení historie",v["title"],ip=self.client_address[0])
            return self.redirect(f"/history?id={v['item_id']}")
        if path=="/users" and user["is_admin"]:
            if len(f.get("password",""))<8:return self.send(400,"Heslo musí mít alespoň 8 znaků")
            try:
                with db() as c:
                    c.execute("INSERT INTO users(username,passhash,is_admin,created) VALUES(?,?,0,?)",(f.get("username",""),pw_hash(f["password"]),int(time.time())))
                    audit(c,user,"Vytvoření uživatele",f.get("username",""),ip=self.client_address[0])
            except sqlite3.IntegrityError:return self.send(409,"Uživatel již existuje")
            return self.redirect("/users")
        if path=="/reset-password" and user["is_admin"]:
            if len(f.get("password",""))<8:return self.send(400,"Heslo musí mít alespoň 8 znaků")
            with db() as c:
                target=c.execute("SELECT username FROM users WHERE id=?",(f.get("user_id"),)).fetchone()
                if not target:return self.send(404,"Uživatel neexistuje")
                c.execute("UPDATE users SET passhash=? WHERE id=?",(pw_hash(f["password"]),f["user_id"])); c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?",(f["user_id"],)); audit(c,user,"Změna hesla uživatele",target["username"],"Aktivní relace ukončeny",self.client_address[0])
            return self.redirect("/users")
        if path=="/remove-user" and user["is_admin"]:
            try:target_id=int(f.get("user_id","0"))
            except ValueError:return self.send(400,"Neplatný uživatel")
            with db() as c:
                first_admin=c.execute("SELECT MIN(id) FROM users WHERE is_admin=1").fetchone()[0]
                target=c.execute("SELECT username,active FROM users WHERE id=?",(target_id,)).fetchone()
                if not target:return self.send(404,"Uživatel neexistuje")
                if target_id in (user["id"],first_admin):return self.send(403,"Prvního administrátora ani vlastní účet nelze odstranit")
                c.execute("UPDATE users SET active=0 WHERE id=?",(target_id,)); c.execute("UPDATE sessions SET revoked=1 WHERE user_id=?",(target_id,)); audit(c,user,"Odebrání uživatele",target["username"],"Účet deaktivován a relace ukončeny",self.client_address[0])
            return self.redirect("/users")
        if path=="/restore-user" and user["is_admin"]:
            with db() as c:
                target=c.execute("SELECT username FROM users WHERE id=?",(f.get("user_id"),)).fetchone()
                if not target:return self.send(404,"Uživatel neexistuje")
                c.execute("UPDATE users SET active=1 WHERE id=?",(f["user_id"],)); audit(c,user,"Obnovení uživatele",target["username"],"Účet aktivován",self.client_address[0])
            return self.redirect("/users")
        if path=="/change-password":
            current=f.get("current_password",""); new=f.get("new_password",""); confirm=f.get("confirm_password","")
            if not pw_ok(current,user["passhash"]):return self.send(400,"Současné heslo není správné")
            if len(new)<8:return self.send(400,"Nové heslo musí mít alespoň 8 znaků")
            if new!=confirm:return self.send(400,"Nová hesla se neshodují")
            if pw_ok(new,user["passhash"]):return self.send(400,"Nové heslo musí být jiné než současné")
            with db() as c:
                c.execute("UPDATE users SET passhash=? WHERE id=?",(pw_hash(new),user["id"])); c.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash<>?",(user["id"],token_hash(self.session_token()))); audit(c,user,"Změna vlastního hesla",user["username"],"Ostatní relace ukončeny",self.client_address[0])
            return self.redirect("/account?changed=1")
        if path=="/revoke-session":
            with db() as c:
                s=c.execute("SELECT sessions.*,users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.id=?",(f.get("session_id"),)).fetchone()
                if not s:return self.send(404,"Relace neexistuje")
                if s["user_id"]!=user["id"] and not user["is_admin"]:return self.send(403,"Relaci nelze ukončit")
                c.execute("UPDATE sessions SET revoked=1 WHERE id=?",(s["id"],)); audit(c,user,"Ukončení relace",s["username"],s["ip"],self.client_address[0])
            if s["token_hash"]==token_hash(self.session_token()):return self.redirect("/",[("Set-Cookie","kc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")])
            return self.redirect("/sessions")
        self.send(404,"Nenalezeno")

if __name__=="__main__":
    init(); print(f"Klíčenka běží na http://{HOST}:{PORT}"); ThreadingHTTPServer((HOST,PORT),App).serve_forever()
