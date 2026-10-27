#!/usr/bin/env python3
"""
ATM 2.0 — Eğitim amaçlı ATM simülasyonu
Çalıştırma:
    pip install fastapi uvicorn sqlalchemy
    python "ATM 2.0.py"
Ardından http://127.0.0.1:8000 adresini açın.

Demo hesaplar:
  TCKN: 11111111111  PIN: 1234
  TCKN: 22222222222  PIN: 0000

Bu uygulama gerçek bankacılık için değildir. Demo hesapları ve yerel SQLite
veritabanı yalnızca eğitim/prototip amacıyla kullanılır.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, date, timezone
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey,
    desc, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

DB_URL = "sqlite:///./atm_v2.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()

SESSION_TTL = 30 * 60
DAILY_WITHDRAW_LIMIT = 20_000_00  # 20.000,00 TL in kuruş
DAILY_TRANSFER_LIMIT = 50_000_00
MAX_SINGLE_TRANSACTION = 20_000_00
ATM_CASH_KURUS = 250_000_00
ATM_BANKNOTS = {20000: 500, 10000: 500, 5000: 500, 2000: 500, 1000: 500}
sessions: dict[str, dict] = {}
login_attempts: dict[str, list[float]] = {}

def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def hash_pin(pin: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 240_000).hex()
    return f"{salt}${digest}"

def verify_pin(pin: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 240_000).hex()
        return hmac.compare_digest(candidate, digest)
    except (ValueError, AttributeError):
        return False

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    tckn = Column(String(11), unique=True, index=True, nullable=False)
    full_name = Column(String(80), nullable=False, default="ATM Kullanıcısı")
    pin_hash = Column(String(200), nullable=False)
    balance_kurus = Column(Integer, nullable=False, default=0)
    savings_kurus = Column(Integer, nullable=False, default=0)
    failed_attempts = Column(Integer, nullable=False, default=0)
    is_blocked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=now_utc, nullable=False)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    tx_type = Column(String(40), nullable=False)
    amount_kurus = Column(Integer, nullable=False)
    balance_after_kurus = Column(Integer, nullable=False, default=0)
    description = Column(String(240), nullable=False, default="")
    reference = Column(String(20), unique=True, nullable=False)
    timestamp = Column(DateTime, default=now_utc, index=True, nullable=False)

class BillPayment(Base):
    __tablename__ = "bill_payments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    bill_type = Column(String(40), nullable=False)
    subscriber_no = Column(String(32), nullable=False)
    amount_kurus = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=now_utc, nullable=False)
    reference = Column(String(20), unique=True, nullable=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def money(kurus: int) -> str:
    return f"{kurus // 100:,}".replace(",", ".") + f",{abs(kurus) % 100:02d}"

def new_reference() -> str:
    return "ATM" + secrets.token_hex(5).upper()

def add_tx(db: Session, user: User, tx_type: str, amount: int, desc_text: str) -> Transaction:
    tx = Transaction(
        user_id=user.id, tx_type=tx_type, amount_kurus=amount,
        balance_after_kurus=user.balance_kurus, description=desc_text,
        reference=new_reference(), timestamp=now_utc()
    )
    db.add(tx)
    return tx

def require_session(x_token: Optional[str] = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not x_token or x_token not in sessions:
        raise HTTPException(401, "Oturumunuz sona ermiş. Lütfen tekrar giriş yapın.")
    sess = sessions[x_token]
    if sess["expires"] < time.time():
        sessions.pop(x_token, None)
        raise HTTPException(401, "Oturum süreniz doldu. Lütfen tekrar giriş yapın.")
    user = db.query(User).filter(User.id == sess["user_id"]).first()
    if not user or user.is_blocked:
        sessions.pop(x_token, None)
        raise HTTPException(401, "Oturum geçersiz veya hesap bloke.")
    sess["expires"] = time.time() + SESSION_TTL
    return user

class LoginRequest(BaseModel):
    tckn: str = Field(min_length=11, max_length=11, pattern=r"^\d{11}$")
    pin: str = Field(min_length=4, max_length=6, pattern=r"^\d{4,6}$")

class AmountRequest(BaseModel):
    amount: float = Field(gt=0, le=20000, allow_inf_nan=False)
    @field_validator("amount")
    @classmethod
    def cents_precision(cls, value: float) -> float:
        if round(value * 100) != value * 100:
            raise ValueError("Tutar en fazla iki ondalık basamak içerebilir.")
        return value

class TransferRequest(AmountRequest):
    target_tckn: str = Field(min_length=11, max_length=11, pattern=r"^\d{11}$")

class PinRequest(BaseModel):
    current_pin: str = Field(min_length=4, max_length=6, pattern=r"^\d{4,6}$")
    new_pin: str = Field(min_length=4, max_length=6, pattern=r"^\d{4,6}$")

class SavingsRequest(AmountRequest):
    direction: str = Field(pattern=r"^(to_savings|to_main)$")

class BillRequest(AmountRequest):
    bill_type: str = Field(pattern=r"^(Elektrik|Su|Doğalgaz|İnternet)$")
    subscriber_no: str = Field(min_length=4, max_length=32, pattern=r"^[A-Za-z0-9-]+$")

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(User).first():
            db.add_all([
                User(tckn="11111111111", full_name="Demo Kullanıcı", pin_hash=hash_pin("1234"), balance_kurus=550000),
                User(tckn="22222222222", full_name="Ayşe Demir", pin_hash=hash_pin("0000"), balance_kurus=125000),
            ])
            db.commit()
    finally:
        db.close()
    yield
    sessions.clear()

app = FastAPI(title="ATM 2.0", version="2.0.0", lifespan=lifespan)

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.post("/api/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    ip_key = "local"
    recent = [t for t in login_attempts.get(ip_key, []) if time.time() - t < 60]
    login_attempts[ip_key] = recent
    if len(recent) >= 12:
        raise HTTPException(429, "Çok fazla giriş denemesi. Bir dakika sonra tekrar deneyin.")
    user = db.query(User).filter(User.tckn == req.tckn).first()
    if not user or user.is_blocked or not verify_pin(req.pin, user.pin_hash):
        login_attempts[ip_key].append(time.time())
        if user and not user.is_blocked:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.is_blocked = True
            db.commit()
        # Avoid revealing whether a particular TCKN exists.
        raise HTTPException(403, "Kimlik numarası veya PIN hatalı; hesap bloke olabilir.")
    user.failed_attempts = 0
    db.commit()
    token = secrets.token_urlsafe(32)
    sessions[token] = {"user_id": user.id, "expires": time.time() + SESSION_TTL}
    return {"token": token, "name": user.full_name, "balance": user.balance_kurus / 100,
            "savings": user.savings_kurus / 100, "expires_in": SESSION_TTL}

@app.post("/api/logout")
def logout(x_token: Optional[str] = Header(default=None)):
    if x_token:
        sessions.pop(x_token, None)
    return {"message": "Güvenli çıkış yapıldı."}

@app.get("/api/account")
def account(user: User = Depends(require_session)):
    return {"name": user.full_name, "masked_tckn": user.tckn[:3] + "******" + user.tckn[-2:],
            "balance": user.balance_kurus / 100, "savings": user.savings_kurus / 100,
            "blocked": user.is_blocked}

@app.get("/api/balance")
def balance(user: User = Depends(require_session)):
    return {"balance": user.balance_kurus / 100, "savings": user.savings_kurus / 100}

def amount_to_kurus(amount: float) -> int:
    return int(round(amount * 100))

def daily_total(db: Session, user: User, tx_types: tuple[str, ...]) -> int:
    start = datetime.combine(date.today(), datetime.min.time())
    result = db.query(func.coalesce(func.sum(-Transaction.amount_kurus), 0)).filter(
        Transaction.user_id == user.id,
        Transaction.tx_type.in_(tx_types),
        Transaction.timestamp >= start,
        Transaction.amount_kurus < 0
    ).scalar()
    return int(result or 0)

def make_banknotes(amount_kurus: int) -> Optional[dict[int, int]]:
    remaining = amount_kurus
    result = {}
    for note in sorted(ATM_BANKNOTS, reverse=True):
        count = min(remaining // note, ATM_BANKNOTS[note])
        if count:
            result[note] = count
            remaining -= note * count
    return result if remaining == 0 else None

@app.post("/api/withdraw")
def withdraw(req: AmountRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    amount = amount_to_kurus(req.amount)
    if amount % 1000 != 0:
        raise HTTPException(400, "Bu ATM'de çekim tutarı 10 TL ve katları olmalıdır.")
    if amount > MAX_SINGLE_TRANSACTION:
        raise HTTPException(400, "Tek işlem limiti 20.000 TL.")
    if amount > user.balance_kurus:
        raise HTTPException(400, "Yetersiz bakiye.")
    if daily_total(db, user, ("Para Çekme",)) + amount > DAILY_WITHDRAW_LIMIT:
        raise HTTPException(400, "Günlük 20.000 TL para çekme limitiniz aşılır.")
    notes = make_banknotes(amount)
    if notes is None:
        raise HTTPException(400, "ATM'de bu tutarı karşılayacak uygun banknot bulunmuyor.")
    try:
        user.balance_kurus -= amount
        add_tx(db, user, "Para Çekme", -amount, "ATM'den nakit çekim")
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "İşlem tamamlanamadı. Bakiyeniz değiştirilmedi.")
    return {"message": f"{money(amount)} TL çekildi.", "balance": user.balance_kurus / 100,
            "reference": db.query(Transaction).filter_by(user_id=user.id).order_by(desc(Transaction.id)).first().reference,
            "banknotes": [{"value": note / 100, "count": count} for note, count in notes.items()]}

@app.post("/api/deposit")
def deposit(req: AmountRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    amount = amount_to_kurus(req.amount)
    if amount > MAX_SINGLE_TRANSACTION:
        raise HTTPException(400, "Tek işlem limiti 20.000 TL.")
    try:
        user.balance_kurus += amount
        add_tx(db, user, "Para Yatırma", amount, "ATM'ye para yatırma")
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "İşlem tamamlanamadı. Bakiyeniz değiştirilmedi.")
    return {"message": f"{money(amount)} TL yatırıldı.", "balance": user.balance_kurus / 100,
            "reference": db.query(Transaction).filter_by(user_id=user.id).order_by(desc(Transaction.id)).first().reference}

@app.post("/api/transfer")
def transfer(req: TransferRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    amount = amount_to_kurus(req.amount)
    if amount > MAX_SINGLE_TRANSACTION:
        raise HTTPException(400, "Tek transfer limiti 20.000 TL.")
    if req.target_tckn == user.tckn:
        raise HTTPException(400, "Kendinize transfer yapamazsınız.")
    target = db.query(User).filter(User.tckn == req.target_tckn).first()
    if not target or target.is_blocked:
        raise HTTPException(404, "Alıcı hesap bulunamadı veya kullanılamıyor.")
    if amount > user.balance_kurus:
        raise HTTPException(400, "Yetersiz bakiye.")
    if daily_total(db, user, ("Transfer Giden",)) + amount > DAILY_TRANSFER_LIMIT:
        raise HTTPException(400, "Günlük 50.000 TL transfer limitiniz aşılır.")
    try:
        user.balance_kurus -= amount
        target.balance_kurus += amount
        add_tx(db, user, "Transfer Giden", -amount, f"{target.full_name} adlı alıcıya transfer")
        add_tx(db, target, "Transfer Gelen", amount, f"{user.full_name} adlı gönderenden transfer")
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "Transfer tamamlanamadı. Lütfen tekrar kontrol edin.")
    return {"message": f"{target.full_name} adlı alıcıya {money(amount)} TL gönderildi.",
            "balance": user.balance_kurus / 100,
            "reference": db.query(Transaction).filter_by(user_id=user.id).order_by(desc(Transaction.id)).first().reference}

@app.post("/api/pin")
def change_pin(req: PinRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    if not verify_pin(req.current_pin, user.pin_hash):
        raise HTTPException(400, "Mevcut PIN hatalı.")
    if req.current_pin == req.new_pin:
        raise HTTPException(400, "Yeni PIN mevcut PIN'den farklı olmalı.")
    if req.new_pin in ("0000", "1111", "1234", user.tckn[-4:]):
        raise HTTPException(400, "Daha güçlü, kolay tahmin edilemeyen bir PIN seçin.")
    user.pin_hash = hash_pin(req.new_pin)
    db.commit()
    # Rotate sessions: the current user must log in again.
    for token in [k for k, v in sessions.items() if v["user_id"] == user.id]:
        sessions.pop(token, None)
    return {"message": "PIN değiştirildi. Güvenlik için tekrar giriş yapın."}

@app.post("/api/savings")
def savings(req: SavingsRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    amount = amount_to_kurus(req.amount)
    if amount > MAX_SINGLE_TRANSACTION:
        raise HTTPException(400, "Tek işlem limiti 20.000 TL.")
    try:
        if req.direction == "to_savings":
            if amount > user.balance_kurus:
                raise HTTPException(400, "Vadesiz hesap bakiyesi yetersiz.")
            user.balance_kurus -= amount
            user.savings_kurus += amount
            add_tx(db, user, "Birikime Aktarım", -amount, "Birikim hesabına aktarım")
        else:
            if amount > user.savings_kurus:
                raise HTTPException(400, "Birikim hesabı bakiyesi yetersiz.")
            user.savings_kurus -= amount
            user.balance_kurus += amount
            add_tx(db, user, "Birikimden Aktarım", amount, "Vadesiz hesaba aktarım")
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(500, "Aktarım tamamlanamadı.")
    return {"message": "Hesaplar arası aktarım başarılı.", "balance": user.balance_kurus / 100,
            "savings": user.savings_kurus / 100}

@app.post("/api/bills")
def pay_bill(req: BillRequest, user: User = Depends(require_session), db: Session = Depends(get_db)):
    amount = amount_to_kurus(req.amount)
    if amount > 500_000:
        raise HTTPException(400, "Fatura başına üst limit 5.000 TL.")
    if amount > user.balance_kurus:
        raise HTTPException(400, "Fatura ödemesi için bakiye yetersiz.")
    ref = new_reference()
    try:
        user.balance_kurus -= amount
        db.add(BillPayment(user_id=user.id, bill_type=req.bill_type, subscriber_no=req.subscriber_no,
                           amount_kurus=amount, reference=ref, timestamp=now_utc()))
        add_tx(db, user, "Fatura Ödeme", -amount, f"{req.bill_type} faturası • Abone: {req.subscriber_no}")
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "Fatura ödemesi tamamlanamadı.")
    return {"message": f"{req.bill_type} faturası ödendi.", "reference": ref,
            "balance": user.balance_kurus / 100}

@app.get("/api/transactions")
def transactions(
    kind: str = "Tümü", limit: int = 50, offset: int = 0,
    user: User = Depends(require_session), db: Session = Depends(get_db)
):
    allowed = {"Tümü", "Para Çekme", "Para Yatırma", "Transfer Giden", "Transfer Gelen",
               "Fatura Ödeme", "Birikime Aktarım", "Birikimden Aktarım"}
    if kind not in allowed:
        raise HTTPException(400, "Geçersiz işlem filtresi.")
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    query = db.query(Transaction).filter(Transaction.user_id == user.id)
    if kind != "Tümü":
        query = query.filter(Transaction.tx_type == kind)
    total = query.count()
    rows = query.order_by(desc(Transaction.timestamp), desc(Transaction.id)).offset(offset).limit(limit).all()
    return {"total": total, "transactions": [{
        "id": tx.id, "tx_type": tx.tx_type, "amount": tx.amount_kurus / 100,
        "balance_after": tx.balance_after_kurus / 100,
        "description": tx.description, "reference": tx.reference,
        "timestamp": tx.timestamp.isoformat() + "Z"
    } for tx in rows]}

HTML = r"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATM 2.0 | Dijital Bankacılık</title>
<style>
:root{--red:#df1537;--red2:#b70d2b;--ink:#172033;--muted:#738096;--line:#e7eaf0;--bg:#f3f5f9;--green:#12845b;--shadow:0 24px 70px #14213d12}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#ffe5eb 0,transparent 35%),radial-gradient(ellipse at 100% 100%,#e3eaff 0,transparent 35%),var(--bg);font-family:Inter,"Segoe UI",Arial,sans-serif;color:var(--ink);min-height:100vh}
button,input,select{font:inherit}button{cursor:pointer;transition:.18s ease}button:disabled{opacity:.55;cursor:wait}
.topbar{height:76px;display:flex;align-items:center;justify-content:space-between;padding:0 max(24px,calc((100vw - 1160px)/2));background:#ffffffd9;border-bottom:1px solid #e9eaf0;backdrop-filter:blur(16px);position:sticky;top:0;z-index:5}
.brand{display:flex;align-items:center;gap:12px;font-weight:850;letter-spacing:-.5px}.brandmark{height:42px;width:42px;background:var(--red);color:white;border-radius:14px;display:grid;place-items:center;font-size:22px;box-shadow:0 7px 16px #df15373a}.brand small{display:block;font-size:11px;color:var(--muted);letter-spacing:1.8px;margin-top:2px}
.top-right{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:13px}.live-dot{height:8px;width:8px;background:#19b47a;border-radius:50%;display:inline-block;margin-right:6px}
.shell{max-width:1160px;margin:34px auto;padding:0 22px 44px}.login-wrap{max-width:920px;margin:45px auto;display:grid;grid-template-columns:1.05fr .95fr;background:#fff;border:1px solid #fff;border-radius:28px;overflow:hidden;box-shadow:var(--shadow);min-height:540px}
.login-hero{padding:52px 44px;background:linear-gradient(145deg,#d80e32,#a9082b);color:white;position:relative;overflow:hidden}.login-hero:after{content:"";position:absolute;width:340px;height:340px;border:1px solid #ffffff24;border-radius:50%;right:-120px;bottom:-110px;box-shadow:0 0 0 35px #ffffff0a,0 0 0 75px #ffffff08}
.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;font-weight:800;opacity:.8}.login-hero h1{font-size:43px;line-height:1.08;letter-spacing:-1.8px;margin:22px 0 18px}.login-hero p{line-height:1.7;color:#ffe2e8;max-width:320px}.hero-foot{position:absolute;bottom:32px;font-size:12px;color:#ffd2db;z-index:1}
.login-panel{padding:48px 42px;display:flex;flex-direction:column;justify-content:center}.login-panel h2{font-size:27px;margin:0 0 8px;letter-spacing:-.7px}.sub{font-size:14px;color:var(--muted);line-height:1.6;margin:0 0 27px}
.label{display:block;font-size:12px;font-weight:750;margin:0 0 8px;color:#465168}.field{width:100%;padding:14px 15px;border:1px solid #dfe3eb;border-radius:12px;outline:none;background:#fbfcfe;margin-bottom:18px;transition:.2s}.field:focus{border-color:var(--red);box-shadow:0 0 0 4px #df153712;background:white}
.primary{border:0;background:var(--red);color:white;border-radius:12px;padding:14px 18px;font-weight:800;box-shadow:0 7px 15px #df153725}.primary:hover{background:var(--red2);transform:translateY(-1px)}.secondary{border:1px solid var(--line);background:white;color:#374157;border-radius:11px;padding:11px 14px;font-weight:700}.secondary:hover{border-color:#d2a0aa;background:#fff8fa}.danger{border:1px solid #f2c8d0;background:#fff4f6;color:#bd1836;border-radius:11px;padding:11px 14px;font-weight:700}
.demo{margin-top:18px;padding:13px 14px;background:#f8f9fc;border:1px solid var(--line);border-radius:12px;color:var(--muted);font-size:12px;line-height:1.8}.demo b{color:#39445a}
.hidden{display:none!important}.dashboard-head{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:24px}.dashboard-head h1{font-size:29px;letter-spacing:-1px;margin:0 0 7px}.dashboard-head p{margin:0;color:var(--muted);font-size:14px}.pill{padding:8px 11px;border-radius:999px;background:#e7f7f0;color:#13835a;font-weight:750;font-size:11px;white-space:nowrap}
.layout{display:grid;grid-template-columns:235px 1fr;gap:22px}.sidebar,.panel{background:#fff;border:1px solid #eaedf2;border-radius:20px;box-shadow:0 6px 24px #14213d07}.sidebar{padding:14px;height:max-content}.navbtn{width:100%;display:flex;align-items:center;gap:12px;padding:13px 14px;border:0;background:transparent;border-radius:12px;color:#6c778b;text-align:left;font-size:13px;font-weight:700;margin:2px 0}.navbtn .ico{width:26px;height:26px;border-radius:8px;background:#f2f4f8;display:grid;place-items:center;font-size:15px}.navbtn:hover{background:#faf0f2;color:var(--red)}.navbtn.active{background:#fff0f3;color:var(--red)}.navbtn.active .ico{background:#ffe0e7}.nav-divider{height:1px;background:var(--line);margin:12px 4px}.side-note{padding:12px 10px;color:#929bad;font-size:11px;line-height:1.6}
.content{min-width:0;display:flex;flex-direction:column;gap:18px}.balance-grid{display:grid;grid-template-columns:1.3fr .7fr;gap:16px}.balance-card{padding:25px;border-radius:19px;color:white;background:linear-gradient(120deg,#1c2438,#303d59);position:relative;overflow:hidden;min-height:190px}.balance-card:after{content:"";position:absolute;width:240px;height:240px;border:1px solid #ffffff18;border-radius:50%;right:-60px;top:-120px;box-shadow:0 0 0 25px #ffffff08,0 0 0 55px #ffffff05}.balance-card .muted-light{color:#b8c1d3;font-size:12px}.balance-amount{font-size:34px;letter-spacing:-1.3px;font-weight:850;margin:12px 0 18px;position:relative;z-index:1}.balance-bottom{display:flex;justify-content:space-between;align-items:center;gap:10px;font-size:12px;color:#c2cada;position:relative;z-index:1}.mini-card{padding:23px;border:1px solid var(--line);border-radius:18px;display:flex;flex-direction:column;justify-content:space-between}.mini-icon{width:40px;height:40px;border-radius:12px;background:#fff0f3;color:var(--red);display:grid;place-items:center;font-size:20px}.mini-card .amount{font-size:23px;font-weight:850;margin:10px 0 5px;letter-spacing:-.5px}.mini-card small{color:var(--muted)}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:17px}.section-head h3{font-size:16px;margin:0;letter-spacing:-.3px}.section-head span{font-size:12px;color:var(--muted)}.panel{padding:22px}.quick-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}.quick{padding:17px 12px;text-align:left;border:1px solid var(--line);background:white;border-radius:14px;color:var(--ink)}.quick:hover{border-color:#efb2bf;transform:translateY(-2px);box-shadow:0 8px 18px #df15370b}.quick .qico{font-size:22px;margin-bottom:12px}.quick strong{display:block;font-size:13px;margin-bottom:5px}.quick small{font-size:11px;color:var(--muted);line-height:1.5}
.tx-row{display:grid;grid-template-columns:42px 1fr auto;align-items:center;gap:12px;padding:14px 0;border-bottom:1px solid #eff1f5}.tx-row:last-child{border-bottom:0}.tx-icon{width:40px;height:40px;border-radius:13px;background:#f2f4f8;display:grid;place-items:center;font-size:17px}.tx-title{font-size:13px;font-weight:800}.tx-desc{font-size:11px;color:var(--muted);margin-top:4px;max-width:340px;overflow-wrap:anywhere}.tx-right{text-align:right;font-weight:850;font-size:13px;white-space:nowrap}.positive{color:var(--green)}.negative{color:var(--red)}.tx-date{font-size:10px;color:#8a94a6;font-weight:500;margin-top:5px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 15px}.span2{grid-column:1/-1}.hint{color:var(--muted);font-size:12px;line-height:1.6}.form-actions{display:flex;gap:10px;flex-wrap:wrap}.form-actions button{min-width:130px}.amount-presets{display:flex;gap:8px;flex-wrap:wrap;margin:-5px 0 18px}.preset{padding:8px 12px;background:#fff5f7;border:1px solid #f5d3db;border-radius:9px;color:#b91031;font-size:12px;font-weight:800}
.filter-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}.filter-row select,.filter-row input{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:white;color:var(--ink)}.filter-row input{flex:1;min-width:160px}
.toast{position:fixed;right:24px;bottom:24px;max-width:min(390px,calc(100vw - 32px));background:#172033;color:white;border-radius:14px;padding:15px 18px;box-shadow:0 12px 40px #17203330;z-index:20;font-size:13px;line-height:1.5}.toast.error{background:#a80e2b}.toast.success{background:#11684b}
.receipt{border:1px dashed #cbd1dc;background:#fafbfe;padding:18px;border-radius:12px;margin:15px 0;font-size:13px;line-height:1.8}.receipt h4{margin:0 0 10px}.receipt-row{display:flex;justify-content:space-between;gap:12px}
.footer{text-align:center;color:#9aa3b2;font-size:11px;margin-top:26px}.badge{display:inline-flex;background:#f1f3f8;color:#59657b;padding:5px 8px;border-radius:7px;font-size:10px;font-weight:800}
@media(max-width:850px){.login-wrap{margin:25px auto;grid-template-columns:1fr}.login-hero{padding:32px;min-height:240px}.login-hero h1{font-size:34px;margin:15px 0}.hero-foot{position:relative;bottom:auto;margin-top:25px}.login-panel{padding:32px}.layout{grid-template-columns:1fr}.sidebar{display:grid;grid-template-columns:repeat(3,1fr);gap:4px}.navbtn{justify-content:center;padding:10px 5px;font-size:11px}.navbtn .ico{display:none}.nav-divider,.side-note{display:none}.balance-grid{grid-template-columns:1fr 1fr}.balance-card{grid-column:1/-1}.quick-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:520px){.topbar{height:65px;padding:0 16px}.top-right .status-text{display:none}.shell{padding:0 13px 30px;margin:23px auto}.dashboard-head{align-items:flex-start}.dashboard-head h1{font-size:24px}.pill{font-size:10px}.sidebar{grid-template-columns:repeat(3,1fr);padding:7px}.navbtn{font-size:10px}.panel{padding:17px}.balance-card{padding:21px;min-height:175px}.balance-amount{font-size:30px}.balance-grid{gap:10px}.mini-card{padding:16px}.mini-card .amount{font-size:19px}.form-grid{grid-template-columns:1fr}.span2{grid-column:auto}.login-panel{padding:26px 22px}.login-hero{padding:28px 24px}.login-hero h1{font-size:31px}.tx-row{grid-template-columns:36px 1fr auto;gap:8px}.tx-icon{width:34px;height:34px}.tx-right{font-size:12px}.tx-desc{max-width:180px}.section-head{align-items:flex-start}.topbar .brand{font-size:14px}.brandmark{width:36px;height:36px}}
@media print{body{background:white}.topbar,.sidebar,.no-print,.footer{display:none!important}.shell{margin:0;max-width:none}.layout{display:block}.panel{box-shadow:none}.receipt{border:1px dashed #777}}
</style></head><body>
<header class="topbar"><div class="brand"><div class="brandmark">Z</div><div>ATM 2.0<small>DİJİTAL BANKACILIK</small></div></div><div class="top-right"><span><i class="live-dot"></i><span class="status-text">Sistem aktif</span></span><span id="clock"></span></div></header>
<main class="shell">
<section id="login-view" class="login-wrap">
 <div class="login-hero"><div class="eyebrow">Yeni nesil ATM deneyimi</div><h1>Bankacılık<br>artık daha<br>kolay.</h1><p>Hesabını yönet, işlemlerini güvenle tamamla ve paranı tek ekrandan kontrol et.</p><div class="hero-foot">Güvenli oturum • Anlık bakiye • İşlem takibi</div></div>
 <div class="login-panel"><div class="eyebrow" style="color:var(--red)">Hoş geldin</div><h2>Hesabına giriş yap</h2><p class="sub">Devam etmek için demo kart bilgilerini gir.</p>
 <form id="login-form"><label class="label" for="tckn">T.C. kimlik numarası</label><input class="field" id="tckn" inputmode="numeric" autocomplete="username" maxlength="11" placeholder="11 haneli kimlik numarası" required>
 <label class="label" for="pin">Kart PIN'i</label><input class="field" id="pin" type="password" inputmode="numeric" autocomplete="current-password" maxlength="6" placeholder="4–6 haneli PIN" required>
 <button class="primary" id="login-button" type="submit" style="width:100%">Güvenli giriş <span style="float:right">→</span></button></form>
 <div class="demo"><b>DEMO HESAPLARI</b><br>Kimlik: <b>11111111111</b> · PIN: <b>1234</b><br>Kimlik: <b>22222222222</b> · PIN: <b>0000</b><br><span>Yalnızca eğitim amaçlıdır; gerçek bilgilerinizi kullanmayın.</span></div></div>
</section>
<section id="app-view" class="hidden">
 <div class="dashboard-head"><div><h1 id="welcome">Merhaba 👋</h1><p>Finansal durumun ve işlemlerin tek bakışta.</p></div><div class="pill">● HESAP GÜVENLİ</div></div>
 <div class="layout"><aside class="sidebar no-print">
 <button class="navbtn active" data-page="dashboard"><span class="ico">⌂</span>Genel Bakış</button>
 <button class="navbtn" data-page="withdraw"><span class="ico">↗</span>Para Çek</button>
 <button class="navbtn" data-page="deposit"><span class="ico">↙</span>Para Yatır</button>
 <button class="navbtn" data-page="transfer"><span class="ico">⇄</span>Transfer</button>
 <button class="navbtn" data-page="history"><span class="ico">▤</span>Hesap Özeti</button>
 <button class="navbtn" data-page="savings"><span class="ico">◈</span>Birikim Hesabı</button>
 <button class="navbtn" data-page="bills"><span class="ico">▦</span>Fatura Öde</button>
 <button class="navbtn" data-page="settings"><span class="ico">⚙</span>Güvenlik</button>
 <div class="nav-divider"></div><button class="navbtn" id="logout"><span class="ico">↪</span>Güvenli Çıkış</button>
 <div class="side-note">Bu arayüz bir eğitim simülasyonudur. Gerçek banka sistemi değildir.</div>
 </aside><div class="content">
 <section id="page-dashboard" class="page">
  <div class="balance-grid"><div class="balance-card"><div class="muted-light">VADESİZ HESAP BAKİYESİ</div><div class="balance-amount" id="main-balance">₺0,00</div><div class="balance-bottom"><span id="masked-tckn">Hesap: —</span><span>● Kullanıma hazır</span></div></div>
  <div class="mini-card"><div class="mini-icon">◈</div><div><small>Birikim hesabı</small><div class="amount" id="mini-savings">₺0,00</div><small>Geleceğin için biriktir</small></div><button class="secondary" data-go="savings" style="margin-top:14px">Yönet →</button></div></div>
  <div class="panel"><div class="section-head"><h3>Hızlı işlemler</h3><span>Tek dokunuşla başla</span></div><div class="quick-grid">
  <button class="quick" data-go="withdraw"><div class="qico">↗</div><strong>Para çek</strong><small>ATM'den nakit al</small></button>
  <button class="quick" data-go="deposit"><div class="qico">↙</div><strong>Para yatır</strong><small>Bakiyeni artır</small></button>
  <button class="quick" data-go="transfer"><div class="qico">⇄</div><strong>Transfer</strong><small>Başka hesaba gönder</small></button>
  <button class="quick" data-go="bills"><div class="qico">▦</div><strong>Fatura öde</strong><small>Ödemeni tamamla</small></button></div></div>
  <div class="panel"><div class="section-head"><h3>Son işlemler</h3><button class="secondary" data-go="history">Tümünü gör →</button></div><div id="recent-list"><p class="hint">İşlemler yükleniyor…</p></div></div>
 </section>
 <section id="page-withdraw" class="page hidden"><div class="panel"><div class="section-head"><h3>💸 Para çekme</h3><span class="badge">Günlük limit: 20.000 TL</span></div><p class="hint">ATM'den çekmek istediğin tutarı seç. Bu simülasyonda çekim tutarı 10 TL katı olmalıdır.</p><div class="amount-presets"><button class="preset" data-amount="500" data-target="withdraw-amount">₺500</button><button class="preset" data-amount="1000" data-target="withdraw-amount">₺1.000</button><button class="preset" data-amount="2000" data-target="withdraw-amount">₺2.000</button><button class="preset" data-amount="5000" data-target="withdraw-amount">₺5.000</button></div><form id="withdraw-form"><label class="label">Çekilecek tutar (TL)</label><input class="field" id="withdraw-amount" type="number" min="10" max="20000" step="10" placeholder="Örn. 1000" required><div class="form-actions"><button class="primary">Para çekmeyi onayla</button><button type="button" class="secondary" data-go="dashboard">Vazgeç</button></div></form><div id="withdraw-receipt"></div></div></section>
 <section id="page-deposit" class="page hidden"><div class="panel"><div class="section-head"><h3>💳 Para yatırma</h3><span class="badge">İşlem limiti: 20.000 TL</span></div><p class="hint">Yatırılacak tutarı gir. Bu ekranda nakit sayımı simüle edilir.</p><div class="amount-presets"><button class="preset" data-amount="500" data-target="deposit-amount">₺500</button><button class="preset" data-amount="1000" data-target="deposit-amount">₺1.000</button><button class="preset" data-amount="2500" data-target="deposit-amount">₺2.500</button></div><form id="deposit-form"><label class="label">Yatırılacak tutar (TL)</label><input class="field" id="deposit-amount" type="number" min="0.01" max="20000" step="0.01" placeholder="Örn. 750,50" required><div class="form-actions"><button class="primary">Yatırmayı onayla</button><button type="button" class="secondary" data-go="dashboard">Vazgeç</button></div></form><div id="deposit-receipt"></div></div></section>
 <section id="page-transfer" class="page hidden"><div class="panel"><div class="section-head"><h3>⇄ Para transferi</h3><span class="badge">Günlük limit: 50.000 TL</span></div><p class="hint">Demo hesaplar arasında anında havale simülasyonu. Onaylamadan önce alıcı bilgilerini kontrol et.</p><form id="transfer-form" class="form-grid"><div class="span2"><label class="label">Alıcının T.C. kimlik numarası</label><input class="field" id="transfer-tckn" inputmode="numeric" maxlength="11" placeholder="11 haneli kimlik numarası" required></div><div class="span2"><label class="label">Gönderilecek tutar (TL)</label><input class="field" id="transfer-amount" type="number" min="0.01" max="20000" step="0.01" placeholder="Örn. 250" required></div><div class="span2 form-actions"><button class="primary">Transferi onayla</button><button type="button" class="secondary" data-go="dashboard">Vazgeç</button></div></form><div id="transfer-receipt"></div></div></section>
 <section id="page-history" class="page hidden"><div class="panel"><div class="section-head"><h3>▤ Hesap hareketleri</h3><button class="secondary" id="export-csv">CSV dışa aktar</button></div><div class="filter-row"><select id="history-kind"><option>Tümü</option><option>Para Çekme</option><option>Para Yatırma</option><option>Transfer Giden</option><option>Transfer Gelen</option><option>Fatura Ödeme</option><option>Birikime Aktarım</option><option>Birikimden Aktarım</option></select><input id="history-search" placeholder="İşlem açıklamasında ara…"></div><div id="history-list"></div><div class="form-actions" style="margin-top:15px"><button class="secondary" id="history-more">Daha fazla yükle</button><span class="hint" id="history-count"></span></div></div></section>
 <section id="page-savings" class="page hidden"><div class="panel"><div class="section-head"><h3>◈ Birikim hesabı</h3><span class="badge">Hesaplar arası aktarım</span></div><div class="balance-card" style="margin-bottom:22px;min-height:145px"><div class="muted-light">TOPLAM BİRİKİM</div><div class="balance-amount" id="savings-balance">₺0,00</div><div class="balance-bottom"><span>Biriktirmeye bugün başla</span><span>◈ Birikim</span></div></div><form id="savings-form"><label class="label">İşlem türü</label><select class="field" id="savings-direction"><option value="to_savings">Vadesiz hesaptan birikime aktar</option><option value="to_main">Birikimden vadesiz hesaba aktar</option></select><label class="label">Tutar (TL)</label><input class="field" id="savings-amount" type="number" min="0.01" max="20000" step="0.01" placeholder="Örn. 1000" required><div class="form-actions"><button class="primary">Aktarımı tamamla</button></div></form></div></section>
 <section id="page-bills" class="page hidden"><div class="panel"><div class="section-head"><h3>▦ Fatura ödeme</h3><span class="badge">Demo ödeme</span></div><p class="hint">Gerçek kurumlara ödeme yapılmaz. İşlem yalnızca simülasyon veritabanına kaydedilir.</p><form id="bill-form"><label class="label">Fatura türü</label><select class="field" id="bill-type"><option>Elektrik</option><option>Su</option><option>Doğalgaz</option><option>İnternet</option></select><label class="label">Abone / sözleşme numarası</label><input class="field" id="subscriber-no" maxlength="32" placeholder="Örn. AB-123456" required><label class="label">Ödeme tutarı (TL)</label><input class="field" id="bill-amount" type="number" min="0.01" max="5000" step="0.01" placeholder="Örn. 420,50" required><div class="form-actions"><button class="primary">Faturayı öde</button></div></form><div id="bill-receipt"></div></div></section>
 <section id="page-settings" class="page hidden"><div class="panel"><div class="section-head"><h3>⚙ Güvenlik ayarları</h3><span class="badge">PIN yönetimi</span></div><p class="hint">PIN'ini düzenli olarak değiştir. PIN değişince güvenlik için mevcut oturum kapatılır.</p><form id="pin-form"><label class="label">Mevcut PIN</label><input class="field" id="current-pin" type="password" inputmode="numeric" maxlength="6" required><label class="label">Yeni PIN</label><input class="field" id="new-pin" type="password" inputmode="numeric" minlength="4" maxlength="6" required><label class="label">Yeni PIN (tekrar)</label><input class="field" id="new-pin2" type="password" inputmode="numeric" minlength="4" maxlength="6" required><div class="form-actions"><button class="primary">PIN'i değiştir</button></div></form><div style="margin-top:25px;padding-top:20px;border-top:1px solid var(--line)"><h3 style="font-size:14px">Oturum güvenliği</h3><p class="hint">30 dakika işlem yapılmazsa oturum sona erer. Çıkış yaptığında oturum anahtarı iptal edilir.</p><button class="danger" id="logout2">Güvenli çıkış yap</button></div></div></section>
 </div></div><div class="footer">ATM 2.0 · Eğitim amaçlı simülasyon · Gerçek banka işlemi yapılmaz</div>
</section></main><div id="toast" class="toast hidden" role="status" aria-live="polite"></div>
<script>
let token=null, account=null, historyOffset=0, allTransactions=[], toastTimer=null;
const $=id=>document.getElementById(id);
const fmt=n=>new Intl.NumberFormat('tr-TR',{style:'currency',currency:'TRY'}).format(Number(n)||0);
const escapeHTML=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function notify(msg,type='success'){const t=$('toast');t.textContent=msg;t.className='toast '+type;clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.classList.add('hidden'),3800)}
async function api(path,method='GET',body=null){const headers={'Content-Type':'application/json'};if(token)headers['x-token']=token;let res;try{res=await fetch('/api/'+path,{method,headers,body:body?JSON.stringify(body):null})}catch(e){throw new Error('Sunucuya ulaşılamadı. Uygulamanın çalıştığını kontrol et.')}let data;try{data=await res.json()}catch(e){throw new Error('Sunucudan geçersiz yanıt alındı.')}if(!res.ok){if(res.status===401){token=null;$('app-view').classList.add('hidden');$('login-view').classList.remove('hidden')}throw new Error(data.detail||'İşlem başarısız.')}return data}
function showPage(name){document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));$('page-'+name).classList.remove('hidden');document.querySelectorAll('.navbtn[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===name));if(name==='history')loadHistory(true);if(name==='dashboard')refreshDashboard()}
function receiptHTML(title,data){return `<div class="receipt"><h4>✓ ${escapeHTML(title)}</h4><div class="receipt-row"><span>İşlem referansı</span><b>${escapeHTML(data.reference||'—')}</b></div><div class="receipt-row"><span>İşlem tarihi</span><b>${new Date().toLocaleString('tr-TR')}</b></div><div class="receipt-row"><span>İşlem durumu</span><b style="color:var(--green)">Başarılı</b></div><div class="receipt-row"><span>Kalan bakiye</span><b>${fmt(data.balance)}</b></div><div class="form-actions no-print" style="margin-top:13px"><button class="secondary" onclick="window.print()">Makbuzu yazdır</button></div></div>`}
function txHTML(tx){const positive=tx.amount>0;let icon=tx.tx_type.includes('Transfer')?'⇄':tx.tx_type.includes('Çekme')?'↗':tx.tx_type.includes('Yatırma')?'↙':tx.tx_type.includes('Fatura')?'▦':'◈';return `<div class="tx-row"><div class="tx-icon">${icon}</div><div><div class="tx-title">${escapeHTML(tx.tx_type)}</div><div class="tx-desc">${escapeHTML(tx.description)} · ${escapeHTML(tx.reference)}</div><div class="tx-date">${new Date(tx.timestamp).toLocaleString('tr-TR')}</div></div><div class="tx-right ${positive?'positive':'negative'}">${positive?'+':'−'}${fmt(Math.abs(tx.amount))}<div class="tx-date">Bakiye: ${fmt(tx.balance_after)}</div></div></div>`}
async function refreshDashboard(){if(!token)return;try{account=await api('account');$('welcome').textContent='Merhaba, '+account.name.split(' ')[0]+' 👋';$('masked-tckn').textContent='Hesap: '+account.masked_tckn;$('main-balance').textContent=fmt(account.balance);$('mini-savings').textContent=fmt(account.savings);$('savings-balance').textContent=fmt(account.savings);const d=await api('transactions?limit=5');$('recent-list').innerHTML=d.transactions.length?d.transactions.map(txHTML).join(''):'<p class="hint">Henüz işlem yok. İlk işlemini yaptığında burada görünecek.</p>'}catch(e){notify(e.message,'error')}}
async function loadHistory(reset=false){if(reset){historyOffset=0;allTransactions=[]}$('history-list').innerHTML=reset?'<p class="hint">İşlemler yükleniyor…</p>':$('history-list').innerHTML;try{const kind=encodeURIComponent($('history-kind').value);const d=await api(`transactions?kind=${kind}&limit=50&offset=${historyOffset}`);allTransactions=reset?d.transactions:allTransactions.concat(d.transactions);historyOffset+=d.transactions.length;renderHistory();$('history-count').textContent=`${allTransactions.length} / ${d.total} işlem`; $('history-more').classList.toggle('hidden',historyOffset>=d.total)}catch(e){notify(e.message,'error')}}
function renderHistory(){const q=$('history-search').value.trim().toLocaleLowerCase('tr-TR');const rows=allTransactions.filter(t=>(t.description+' '+t.tx_type+' '+t.reference).toLocaleLowerCase('tr-TR').includes(q));$('history-list').innerHTML=rows.length?rows.map(txHTML).join(''):'<p class="hint">Bu filtreye uygun işlem bulunamadı.</p>'}
async function formAction(formId,fn){$(formId).addEventListener('submit',async e=>{e.preventDefault();const btn=$(formId).querySelector('button[type="submit"],button:not([type])');if(btn){btn.disabled=true;btn.dataset.old=btn.textContent;btn.textContent='İşleniyor…'}try{await fn()}catch(err){notify(err.message,'error')}finally{if(btn){btn.disabled=false;btn.textContent=btn.dataset.old||'Onayla'}}})}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();const b=$('login-button');b.disabled=true;b.textContent='Giriş yapılıyor…';try{const d=await api('login','POST',{tckn:$('tckn').value.trim(),pin:$('pin').value});token=d.token;$('pin').value='';$('login-view').classList.add('hidden');$('app-view').classList.remove('hidden');notify('Hoş geldin, '+d.name+'!');showPage('dashboard')}catch(err){notify(err.message,'error')}finally{b.disabled=false;b.innerHTML='Güvenli giriş <span style="float:right">→</span>'}});
formAction('withdraw-form',async()=>{const amount=Number($('withdraw-amount').value);if(!confirm(fmt(amount)+' çekme işlemini onaylıyor musun?'))return;const d=await api('withdraw','POST',{amount});$('withdraw-receipt').innerHTML=receiptHTML(d.message,d)+`<p class="hint">Banknot simülasyonu: ${d.banknotes.map(n=>`${n.count} × ${fmt(n.value)}`).join(' · ')}</p>`;$('withdraw-amount').value='';notify(d.message);await refreshDashboard()});
formAction('deposit-form',async()=>{const amount=Number($('deposit-amount').value);if(!confirm(fmt(amount)+' yatırma işlemini onaylıyor musun?'))return;const d=await api('deposit','POST',{amount});$('deposit-receipt').innerHTML=receiptHTML(d.message,d);$('deposit-amount').value='';notify(d.message);await refreshDashboard()});
formAction('transfer-form',async()=>{const target_tckn=$('transfer-tckn').value.trim(),amount=Number($('transfer-amount').value);if(!confirm('Alıcı: '+target_tckn+'\nTutar: '+fmt(amount)+'\nTransferi onaylıyor musun?'))return;const d=await api('transfer','POST',{target_tckn,amount});$('transfer-receipt').innerHTML=receiptHTML(d.message,d);$('transfer-tckn').value='';$('transfer-amount').value='';notify(d.message);await refreshDashboard()});
formAction('savings-form',async()=>{const d=await api('savings','POST',{amount:Number($('savings-amount').value),direction:$('savings-direction').value});$('savings-amount').value='';notify(d.message);await refreshDashboard()});
formAction('bill-form',async()=>{const body={bill_type:$('bill-type').value,subscriber_no:$('subscriber-no').value.trim(),amount:Number($('bill-amount').value)};if(!confirm(body.bill_type+' faturası · '+fmt(body.amount)+'\nBu demo ödemesini onaylıyor musun?'))return;const d=await api('bills','POST',body);$('bill-receipt').innerHTML=receiptHTML(d.message,d);$('subscriber-no').value='';$('bill-amount').value='';notify(d.message);await refreshDashboard()});
formAction('pin-form',async()=>{if($('new-pin').value!==$('new-pin2').value)throw new Error('Yeni PIN alanları eşleşmiyor.');const d=await api('pin','POST',{current_pin:$('current-pin').value,new_pin:$('new-pin').value});notify(d.message);token=null;$('app-view').classList.add('hidden');$('login-view').classList.remove('hidden');$('current-pin').value='';$('new-pin').value='';$('new-pin2').value=''});
async function logout(){try{await api('logout','POST')}catch(e){}token=null;account=null;$('app-view').classList.add('hidden');$('login-view').classList.remove('hidden');$('tckn').value='';$('pin').value='';notify('Güvenli çıkış yapıldı.')}
$('logout').addEventListener('click',logout);$('logout2').addEventListener('click',logout);
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.go)));
document.querySelectorAll('[data-amount]').forEach(b=>b.addEventListener('click',()=>{$(b.dataset.target).value=b.dataset.amount}));
$('history-kind').addEventListener('change',()=>loadHistory(true));$('history-search').addEventListener('input',renderHistory);$('history-more').addEventListener('click',()=>loadHistory(false));
$('export-csv').addEventListener('click',()=>{if(!allTransactions.length){notify('Dışa aktarılacak işlem yok.','error');return}const rows=[['Tarih','Tür','Tutar TL','Bakiye TL','Açıklama','Referans'],...allTransactions.map(t=>[new Date(t.timestamp).toLocaleString('tr-TR'),t.tx_type,t.amount.toFixed(2),t.balance_after.toFixed(2),t.description,t.reference])];const csv='\ufeff'+rows.map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(';')).join('\r\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8;'}));a.download='atm-islem-gecmisi.csv';a.click();URL.revokeObjectURL(a.href);notify('CSV dosyası hazırlandı.')});
setInterval(()=>{$('clock').textContent=new Date().toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'})},1000);$('clock').textContent=new Date().toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'});
</script></body></html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
