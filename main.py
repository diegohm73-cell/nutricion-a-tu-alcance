from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime, timedelta, timezone
from pathlib import Path
from openai import OpenAI
import sqlite3, hashlib, os, secrets, json, hmac, re, base64

DB_PATH = Path(__file__).with_name("nutrition_app.db")
PBKDF2_ROUNDS = 210_000
security = HTTPBearer(auto_error=False)
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-luna")

# Para pruebas, si AUTH_SECRET no existe se deriva de OPENAI_API_KEY.
# En producción conviene definir AUTH_SECRET como variable independiente en Render.
_raw_auth_secret = os.getenv("AUTH_SECRET") or ("auth:" + (os.getenv("OPENAI_API_KEY") or ""))
AUTH_SECRET = hashlib.sha256(_raw_auth_secret.encode()).digest()

app = FastAPI(title="Nutrición a tu alcance API", version="0.2.0")
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

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def issue_token(user_id: int):
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "uid": int(user_id),
        "iat": now,
        "exp": now + 30 * 24 * 60 * 60
    }
    body = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    )
    signature = _b64url_encode(
        hmac.new(AUTH_SECRET, body.encode(), hashlib.sha256).digest()
    )
    return f"{body}.{signature}"

def require_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Falta token de acceso")

    token = authorization.split(" ", 1)[1].strip()

    try:
        body, signature = token.split(".", 1)
        expected = _b64url_encode(
            hmac.new(AUTH_SECRET, body.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(401, "Sesión inválida")

        payload = json.loads(_b64url_decode(body).decode())
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            raise HTTPException(401, "Sesión expirada")

        user_id = int(payload["uid"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(401, "Sesión inválida")

    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    if not row:
        raise HTTPException(401, "Usuario no encontrado")

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

class MenuGenerateIn(BaseModel):
    goal: str = Field(min_length=2, max_length=120)
    days: int = Field(default=1, ge=1, le=7)
    kcal: Optional[int] = Field(default=None, ge=800, le=6000)
    meals: int = Field(default=5, ge=3, le=6)
    profile: dict[str, Any] = Field(default_factory=dict)
    clinical: dict[str, Any] = Field(default_factory=dict)
    preferences: dict[str, Any] = Field(default_factory=dict)
    model_config = {"extra":"allow"}

NUTRITION_SYSTEM_PROMPT = """
Eres el motor de generación de menús de la aplicación mexicana "Nutrición a tu alcance".
Tu tarea es crear un menú práctico, realista y clínicamente prudente a partir de los datos
proporcionados por el usuario.

REGLAS OBLIGATORIAS
1. Usa el Sistema Mexicano de Alimentos Equivalentes (SMAE) como marco para calcular cantidades y equivalentes.
2. Todas las porciones deben ser explícitas en unidades domésticas y/o gramos, piezas, mililitros o cucharadas.
3. Cuantifica también verduras, grasas y semillas.
4. Prioriza alimentos reales, accesibles en México y combinaciones culinarias plausibles.
5. Evita menús monótonos y evita acumular varios cereales principales en una misma comida salvo justificación nutricional.
6. Ajusta el menú al objetivo: pérdida de grasa, mantenimiento, ganancia muscular o mejora de hábitos.
7. No uses déficits energéticos agresivos. En menores de 18 años prioriza crecimiento y supervisión profesional.
8. En diabetes tipo 2 distribuye carbohidratos, fibra y proteína; no indiques cambios de dosis de insulina ni medicamentos.
9. En reflujo/gastritis, colon irritable o EII adapta según tolerancia individual sin asumir desencadenantes universales.
10. En cirugía bariátrica respeta estrictamente la fase indicada. Si falta la fase, advierte que debe confirmarse antes de usar el menú.
11. Respeta alergias, intolerancias, alimentos rechazados, cultura, presupuesto y horarios.
12. No diagnostiques enfermedades, no prometas resultados y no sustituyas valoración médica.
13. Si faltan datos clínicos, genera un ejemplo prudente y señala claramente qué debe confirmarse.
14. Si se proporciona un objetivo energético, intenta aproximarte a él y mantén coherencia entre las comidas.
15. El número de días y comidas debe coincidir exactamente con lo solicitado.
16. Devuelve SOLO JSON válido, sin Markdown ni texto antes o después.

FORMATO JSON OBLIGATORIO
{
  "title": "string",
  "goal": "string",
  "target_kcal": 0,
  "disclaimer": "string",
  "clinical_notes": ["string"],
  "smae_notes": ["string"],
  "days": [
    {
      "day": 1,
      "estimated_kcal": 0,
      "meals": [
        {
          "name": "Desayuno",
          "time": "08:00",
          "dish": "string",
          "ingredients": [
            {
              "food": "string",
              "amount": "string",
              "smae_group": "string",
              "equivalents": "string"
            }
          ],
          "instructions": "string",
          "estimated_kcal": 0
        }
      ],
      "daily_notes": ["string"]
    }
  ]
}
"""

def extract_json_object(text: str):
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end+1])
        raise

def build_menu_prompt(data: MenuGenerateIn):
    return (
        "Genera el menú solicitado usando estrictamente las reglas del sistema. "
        "Datos recibidos:\n" +
        json.dumps(data.model_dump(), ensure_ascii=False, indent=2)
    )

def generate_menu_with_ai(data: MenuGenerateIn):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(
            503,
            "El generador no está configurado: falta OPENAI_API_KEY en el servidor"
        )

    client = OpenAI(api_key=api_key)
    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            instructions=NUTRITION_SYSTEM_PROMPT,
            input=build_menu_prompt(data),
            max_output_tokens=8000,
        )
        menu = extract_json_object(response.output_text)
    except json.JSONDecodeError:
        raise HTTPException(502, "El modelo devolvió un menú con formato inválido")
    except Exception as exc:
        raise HTTPException(502, f"No fue posible generar el menú: {type(exc).__name__}")

    if not isinstance(menu, dict) or not isinstance(menu.get("days"), list):
        raise HTTPException(502, "La respuesta del generador no contiene un menú válido")
    if len(menu["days"]) != data.days:
        raise HTTPException(502, "El generador devolvió un número de días distinto al solicitado")

    for day in menu["days"]:
        meals = day.get("meals")
        if not isinstance(meals, list) or len(meals) != data.meals:
            raise HTTPException(502, "El generador devolvió un número de comidas distinto al solicitado")

    return menu

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

@app.post("/menus/generate")
def generate_menu(data: MenuGenerateIn, authorization: str | None = Header(default=None)):
    u = require_user(authorization)

    with conn() as c:
        sub = c.execute(
            "SELECT plan,status FROM subscriptions WHERE user_id=?",
            (u["id"],)
        ).fetchone()

    plan = sub["plan"] if sub else "free"
    status = sub["status"] if sub else "active"

    if status != "active":
        raise HTTPException(403, "La suscripción no está activa")
    if plan == "free" and data.days != 1:
        raise HTTPException(403, "La prueba gratuita permite generar un menú de 1 día")
    if plan in {"monthly","annual"} and data.days > 7:
        raise HTTPException(400, "La versión premium admite hasta 7 días por menú")

    menu = generate_menu_with_ai(data)
    title = str(menu.get("title") or "Plan generado")
    target_kcal = menu.get("target_kcal") or data.kcal

    stored_payload = {
        "_generated_by": "ai",
        "_model": OPENAI_MODEL,
        "_request": data.model_dump(),
        "menu": menu,
    }

    with conn() as c:
        cur = c.execute(
            """INSERT INTO menus(user_id,title,goal,kcal,protein,meals,payload,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                u["id"],
                title,
                data.goal,
                target_kcal,
                None,
                data.meals,
                json.dumps(stored_payload, ensure_ascii=False),
                now_iso(),
            )
        )

    return {"id": cur.lastrowid, "ok": True, "menu": menu}

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
