import os
import secrets

import bcrypt
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, create_engine, func
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ---------- Base de données MySQL ----------
# Modifie USER / PASSWORD selon ta config MySQL
DATABASE_URL = os.getenv(
    "DATABASE_URL", "mysql+pymysql://root:ton_mot_de_passe@localhost:3306/auth_db"
)
# Les hébergeurs (Render, Aiven...) fournissent une URL "postgres://" : on l'adapte pour SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    email = Column(String(190), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Schémas ----------
class RegisterIn(BaseModel):
    nom: str
    prenom: str
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    nom: str
    prenom: str
    password: str


# ---------- App ----------
app = FastAPI(title="Auth + Calculatrice")
TOKENS: dict[str, int] = {}  # token -> user_id (en mémoire)


def hash_pw(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def check_pw(p: str, h: str) -> bool:
    return bcrypt.checkpw(p.encode(), h.encode())


def current_user(
    authorization: str = Header(default=""), db: Session = Depends(get_db)
) -> User:
    token = authorization.replace("Bearer ", "")
    user_id = TOKENS.get(token)
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise HTTPException(401, "Non connecté")
    return user


@app.post("/api/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if len(data.password) < 6:
        raise HTTPException(400, "Mot de passe : 6 caractères minimum")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(409, "Cet email existe déjà")
    db.add(
        User(
            nom=data.nom.strip(),
            prenom=data.prenom.strip(),
            email=data.email,
            password_hash=hash_pw(data.password),
        )
    )
    db.commit()
    return {"message": "Compte créé avec succès"}


@app.post("/api/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    users = (
        db.query(User)
        .filter(
            func.lower(User.nom) == data.nom.strip().lower(),
            func.lower(User.prenom) == data.prenom.strip().lower(),
        )
        .all()
    )
    for u in users:
        if check_pw(data.password, u.password_hash):
            token = secrets.token_urlsafe(32)
            TOKENS[token] = u.id
            return {"token": token, "nom": u.nom, "prenom": u.prenom}
    raise HTTPException(401, "Nom, prénom ou mot de passe incorrect")


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"nom": user.nom, "prenom": user.prenom}


@app.post("/api/logout")
def logout(authorization: str = Header(default="")):
    TOKENS.pop(authorization.replace("Bearer ", ""), None)
    return {"message": "Déconnecté"}


# ---------- Pages ----------
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def page_inscription():
    return FileResponse("static/index.html")


@app.get("/accueil")
def page_accueil():
    return FileResponse("static/accueil.html")


@app.get("/calcul")
def page_calcul():
    return FileResponse("static/calcul.html")
