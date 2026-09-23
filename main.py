from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3, hashlib, os, secrets, json, hmac

DB_PATH = Path(__file__).with_name("nutrition_app.db")
PBKDF2_ROUNDS = 210_000
security = HTTPBearer(auto_error=False)

app = FastAPI(title="Nutrición a tu alcance API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restringir en producción al dominio real
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS profiles(
            user_id INTEGER PRIMARY KEY,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS menus(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            goal TEXT,
            kcal INTEGER,
            protein INTEGER,
            meals INTEGER,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS tracking(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            energy INTEGER,
            hunger INTEGER,
            sleep INTEGER,
            digestion INTEGER,
            adherence INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS subscriptions(
            user_id INTEGER PRIMARY KEY,
            plan TEXT NOT NULL DEFAULT 'free',
            status TEXT NOT NULL DEFAULT 'active',
            provider TEXT,
            provider_customer_id TEXT,
            provider_subscription_id TEXT,
            renews_at TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
init_db()

def hash_password(password: str, salt_hex: str | None = None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return digest.hex(), salt.hex()

def verify_password(password: str, digest_hex: str, salt_hex: str):
    check, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(check, digest_hex)

def issue_token(user_id: int):
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    with conn() as c:
        c.execute("INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                  (token,user_id,expires.isoformat(),now_iso()))
    return token

def require_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Falta token de acceso")
    token = authorization.split(" ",1)[1].strip()
    with conn() as c:
        row = c.execute("""
            SELECT u.* , s.expires_at FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE s.token=?
        """,(token,)).fetchone()
    if not row:
        raise HTTPException(401, "Sesión inválida")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(401, "Sesión expirada")
    return row

def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security)
):
    if credentials is None:
        raise HTTPException(401, "Falta token de acceso")

    authorization = f"{credentials.scheme} {credentials.credentials}"
    return require_user(authorization)

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class ProfileIn(BaseModel):
    model_config = {"extra":"allow"}

class MenuIn(BaseModel):
    title: str = "Plan generado"
    goal: Optional[str] = None
    kcal: Optional[int] = None
    protein: Optional[int] = None
    meals: Optional[int] = None
    payload: Any

class TrackingIn(BaseModel):
    energy: int = Field(ge=1, le=5)
    hunger: int = Field(ge=1, le=5)
    sleep: int = Field(ge=1, le=5)
    digestion: int = Field(ge=1, le=5)
    adherence: int = Field(ge=1, le=5)
    date: Optional[str] = None

@app.get("/health")
def health():
    return {"ok": True, "service": "nutricion-a-tu-alcance-api"}

@app.post("/auth/register")
def register(data: RegisterIn):
    digest, salt = hash_password(data.password)
    try:
        with conn() as c:
            cur = c.execute("INSERT INTO users(name,email,password_hash,password_salt,created_at) VALUES(?,?,?,?,?)",
                            (data.name,data.email.lower(),digest,salt,now_iso()))
            uid = cur.lastrowid
            c.execute("INSERT INTO subscriptions(user_id,plan,status,updated_at) VALUES(?,?,?,?)",
                      (uid,"free","active",now_iso()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Ya existe una cuenta con ese correo")
    return {"token": issue_token(uid), "user":{"id":uid,"name":data.name,"email":data.email.lower()}}

@app.post("/auth/login")
def login(data: LoginIn):
    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE email=?",(data.email.lower(),)).fetchone()
    if not row or not verify_password(data.password,row["password_hash"],row["password_salt"]):
        raise HTTPException(401, "Correo o contraseña incorrectos")
    return {"token":issue_token(row["id"]), "user":{"id":row["id"],"name":row["name"],"email":row["email"]}}

@app.get("/me")
def me(u = Depends(current_user)):
    return {"id":u["id"],"name":u["name"],"email":u["email"]}

@app.get("/profile")
def get_profile(authorization: str | None = Header(default=None)):
    u=require_user(authorization)
    with conn() as c:
        row=c.execute("SELECT payload,updated_at FROM profiles WHERE user_id=?",(u["id"],)).fetchone()
    return {"profile": json.loads(row["payload"]) if row else None, "updated_at": row["updated_at"] if row else None}

@app.put("/profile")
def put_profile(data: ProfileIn, authorization: str | None = Header(default=None)):
    u=require_user(authorization)
    payload=json.dumps(data.model_dump(),ensure_ascii=False)
    with conn() as c:
        c.execute("""INSERT INTO profiles(user_id,payload,updated_at) VALUES(?,?,?)
                     ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
                  (u["id"],payload,now_iso()))
    return {"ok":True}

@app.post("/menus")
def create_menu(data: MenuIn, authorization: str | None = Header(default=None)):
    u=require_user(authorization)
    with conn() as c:
        cur=c.execute("""INSERT INTO menus(user_id,title,goal,kcal,protein,meals,payload,created_at)
                         VALUES(?,?,?,?,?,?,?,?)""",
                      (u["id"],data.title,data.goal,data.kcal,data.protein,data.meals,
                       json.dumps(data.payload,ensure_ascii=False),now_iso()))
    return {"id":cur.lastrowid,"ok":True}

@app.get("/menus")
def list_menus(authorization: str | None = Header(default=None), limit: int = 30):
    u=require_user(authorization)
    limit=max(1,min(limit,100))
    with conn() as c:
        rows=c.execute("""SELECT id,title,goal,kcal,protein,meals,payload,created_at
                          FROM menus WHERE user_id=? ORDER BY id DESC LIMIT ?""",(u["id"],limit)).fetchall()
    return {"items":[{**dict(r),"payload":json.loads(r["payload"])} for r in rows]}

@app.post("/tracking")
def create_tracking(data: TrackingIn, authorization: str | None = Header(default=None)):
    u=require_user(authorization)
    created=data.date or now_iso()
    with conn() as c:
        cur=c.execute("""INSERT INTO tracking(user_id,energy,hunger,sleep,digestion,adherence,created_at)
                         VALUES(?,?,?,?,?,?,?)""",
                      (u["id"],data.energy,data.hunger,data.sleep,data.digestion,data.adherence,created))
    return {"id":cur.lastrowid,"ok":True}

@app.get("/tracking")
def list_tracking(authorization: str | None = Header(default=None), limit: int = 52):
    u=require_user(authorization)
    limit=max(1,min(limit,104))
    with conn() as c:
        rows=c.execute("""SELECT id,energy,hunger,sleep,digestion,adherence,created_at
                          FROM tracking WHERE user_id=? ORDER BY id DESC LIMIT ?""",(u["id"],limit)).fetchall()
    return {"items":[dict(r) for r in rows]}

@app.get("/subscription")
def subscription(authorization: str | None = Header(default=None)):
    u=require_user(authorization)
    with conn() as c:
        row=c.execute("SELECT * FROM subscriptions WHERE user_id=?",(u["id"],)).fetchone()
    return dict(row) if row else {"plan":"free","status":"active"}

@app.post("/subscription/mock")
def mock_subscription(plan: str = "monthly", authorization: str | None = Header(default=None)):
    # Solo para desarrollo. Eliminar al conectar pagos reales.
    u=require_user(authorization)
    if plan not in {"monthly","annual","free"}:
        raise HTTPException(400,"Plan inválido")
    with conn() as c:
        c.execute("""INSERT INTO subscriptions(user_id,plan,status,updated_at) VALUES(?,?,?,?)
                     ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan,status='active',updated_at=excluded.updated_at""",
                  (u["id"],plan,"active",now_iso()))
    return {"ok":True,"plan":plan,"status":"active"}
