# 1) Schema JSON di input (esempio “AI Workspace”)

Immagina un’app AI B2B con piani configurabili per team:

```json
{
  "plan_name": "AI Workspace Custom",
  "currency": "eur",
  "billing_cycle": { "interval": "month", "interval_count": 1 }, 
  "seats": 12,
  "features": {
    "ai_gpu_minutes": 5000,
    "storage_gb": 200,
    "sla": "standard",                 // "standard" | "premium"
    "chat_history_retention_days": 90
  },
  "addons": [
    {"key": "extra_storage_gb", "quantity": 50},   // 50 GB add-on
    {"key": "priority_support", "quantity": 1}
  ],
  "trial_days": 7,
  "customer_hint": {                  // come agganciare il cliente
    "customer_id": null,              // se noto, usa cus_...
    "email": "mario.rossi@example.com",
    "name": "Mario Rossi",
    "internal_customer_ref": "user-42",
    "address": {                      // utile per automatic_tax
      "line1": "Via Roma 1",
      "city": "Milano",
      "postal_code": "20100",
      "country": "IT"
    }
  },
  "ui_options": {
    "allow_promo_codes": true,
    "collect_tax_id": true,
    "collect_billing_address": "auto" // "auto" | "required"
  }
}
```

> Nota: lascia che sia **il backend** a tradurre questa configurazione in **prezzo** e **metadati** Stripe. Non farti passare importi “precalcolati” dal frontend.

---

# 2) Regole di pricing (esempio)

Esempio di listino interno (server-side):

* **Base per seat**: 15 € / seat / mese
* **AI GPU minutes**: inclusi 3.000 min; extra 0,002 € / min oltre 3.000 (per semplicità qui li consideriamo inclusi fino a soglia; l’eventuale consumo extra reale lo potresti fatturare come **metered usage** separato)
* **Storage**: include 100 GB; extra 0,10 € / GB / mese
* **SLA**: `standard` = 0 €, `premium` = +199 € / mese (per account)
* **Add-on**:

  * `extra_storage_gb`: 0,10 € / GB / mese
  * `priority_support`: +99 € / mese

**Due strategie di fatturazione** possibili:

* **Per-seat**: calcoli **unit\_amount\_per\_seat** e passi `quantity = seats` a Checkout.
* **Prezzo unico**: calcoli il **totale mensile** e passi `quantity = 1`.

Qui mostro entrambe (scegli tu, la più comune per team è per-seat).

---

# 3) Orchestrazione lato backend (Python)

Di seguito uno **script modulare** (puoi metterlo in `services/plan_configurator.py` o simile) che:

* valida l’input con Pydantic,
* calcola i prezzi (Decimal, rounding ai cent),
* **risolve/crea Customer** via la **tua API** `/admin/customers` (così garantisci indirizzo valido → niente errori con automatic\_tax),
* **chiama** `/plans/checkout` costruendo il payload corretto (con **idempotenza per singola POST**),
* restituisce la **Checkout URL**.

> Usa le **tue** API già implementate (non chiama Stripe direttamente).
> Assumo che la tua API giri su `API_BASE` e che tu abbia `ADMIN_API_KEY` e `USER_API_KEY`.

```python
# services/plan_configurator.py
from __future__ import annotations

import os, json, uuid, decimal
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional, Dict, Any, List, Literal

import requests
from pydantic import BaseModel, Field, EmailStr, field_validator
from dotenv import load_dotenv

# ---------------------------
# Config
# ---------------------------
load_dotenv()

API_BASE        = os.getenv("API_BASE", "http://localhost:8000").rstrip("/")
ADMIN_API_KEY   = os.getenv("ADMIN_API_KEY", "adminkey123")
USER_API_KEY    = os.getenv("USER_API_KEY",  "userkey456")
SUCCESS_URL     = os.getenv("SUCCESS_URL", "https://tuo-sito.com/success?cs_id={CHECKOUT_SESSION_ID}")
CANCEL_URL      = os.getenv("CANCEL_URL",  "https://tuo-sito.com/cancel")
RETURN_URL      = os.getenv("RETURN_URL",  "https://tuo-sito.com/account")

ADMIN_HEADERS = {"X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json"}
USER_HEADERS  = {"X-API-Key": USER_API_KEY,  "Content-Type": "application/json"}

decimal.getcontext().prec = 28  # precisione alta per calcoli, poi round ai cent

# ---------------------------
# Modelli input del configuratore
# ---------------------------

class BillingCycle(BaseModel):
    interval: Literal["day", "week", "month", "year"] = "month"
    interval_count: int = Field(1, ge=1, le=52)

class Features(BaseModel):
    ai_gpu_minutes: int = Field(3000, ge=0)   # inclusi
    storage_gb: int = Field(100, ge=0)
    sla: Literal["standard", "premium"] = "standard"
    chat_history_retention_days: int = Field(30, ge=0)

class AddOn(BaseModel):
    key: Literal["extra_storage_gb", "priority_support"]
    quantity: int = Field(1, ge=1)

class Address(BaseModel):
    line1: str
    city: str
    postal_code: str
    country: str = Field(..., min_length=2, max_length=2)

class CustomerHint(BaseModel):
    customer_id: Optional[str] = None
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    internal_customer_ref: Optional[str] = None
    address: Optional[Address] = None

class UIOptions(BaseModel):
    allow_promo_codes: bool = True
    collect_tax_id: bool = True
    collect_billing_address: Literal["auto", "required"] = "auto"

class PlanConfiguratorInput(BaseModel):
    plan_name: str = "AI Workspace Custom"
    currency: str = Field("eur", min_length=3, max_length=3)
    billing_cycle: BillingCycle = Field(default_factory=BillingCycle)
    seats: int = Field(1, ge=1)
    features: Features = Field(default_factory=Features)
    addons: List[AddOn] = Field(default_factory=list)
    trial_days: Optional[int] = Field(7, ge=0, le=365)
    customer_hint: CustomerHint
    ui_options: UIOptions = Field(default_factory=UIOptions)

    @field_validator("currency")
    @classmethod
    def _lowercase_currency(cls, v: str):
        return v.lower()

# ---------------------------
# Pricing Engine (esempio)
# ---------------------------

class PriceBreakdown(BaseModel):
    currency: str
    unit_amount_cents_per_seat: int       # se usi fatturazione per-seat
    seat_quantity: int
    flat_monthly_cents: int               # se usi fatturazione flat (quantity=1)
    strategy: Literal["per_seat", "flat"] # quale strategia userai
    notes: Dict[str, Any] = {}

def _cents(x: Decimal) -> int:
    """Converte Decimal in centesimi (arrotondando correttamente)."""
    return int((x * Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

def compute_pricing(payload: PlanConfiguratorInput) -> PriceBreakdown:
    """
    Esempio di calcolo:
    - base_per_seat = 15 €
    - storage incluso = 100 GB; extra = 0,10 €/GB/mese
    - SLA premium = +199 € flat / mese
    - add-on: extra_storage_gb (0,10 €/GB), priority_support (+99 €/mese)
    - GPU minutes: inclusi 3000; extra fatturati con metered (qui ignoriamo extra per semplicità)
    """
    currency = payload.currency

    base_per_seat = Decimal("15.00")
    included_storage_gb = 100
    extra_storage_price_per_gb = Decimal("0.10")
    sla_premium_flat = Decimal("199.00")
    priority_support_flat = Decimal("99.00")

    seats = payload.seats
    storage_gb = payload.features.storage_gb
    sla = payload.features.sla

    # Extra storage calcolato rispetto agli inclusi
    extra_storage_gb = max(storage_gb - included_storage_gb, 0)
    extra_storage_cost = Decimal(extra_storage_gb) * extra_storage_price_per_gb

    # Add-on
    addons_flat = Decimal("0.00")
    for ad in payload.addons:
        if ad.key == "extra_storage_gb":
            addons_flat += Decimal(ad.quantity) * extra_storage_price_per_gb
        elif ad.key == "priority_support":
            addons_flat += priority_support_flat * ad.quantity

    sla_flat = sla_premium_flat if sla == "premium" else Decimal("0.00")

    # Strategia 1: per-seat
    #   Prezzo unitario = base_per_seat + (quota add-on flat ripartita?) -> semplice: solo base per seat,
    #   e mettiamo gli extra FLAT (sla/addon) in flat_monthly. Variante: aumentare unit price per-seat con quota flat/seats.
    # Strategia 2: flat unico
    #   Tutto accorpato in flat_monthly, quantity=1.

    # Esempio: per-seat (unit price = base_per_seat), flat separato per add-on/extra/sla
    unit_amount_per_seat = base_per_seat
    flat_monthly = extra_storage_cost + addons_flat + sla_flat

    return PriceBreakdown(
        currency=currency,
        unit_amount_cents_per_seat=_cents(unit_amount_per_seat),
        seat_quantity=seats,
        flat_monthly_cents=_cents(flat_monthly),
        strategy="per_seat",
        notes={
            "explained": {
                "base_per_seat_eur": str(base_per_seat),
                "extra_storage_gb": extra_storage_gb,
                "extra_storage_cost_eur": str(extra_storage_cost),
                "addons_flat_eur": str(addons_flat),
                "sla_flat_eur": str(sla_flat)
            }
        }
    )

# ---------------------------
# Integrazione con le TUE API
# ---------------------------

def ensure_customer(customer: CustomerHint) -> str:
    """
    Se abbiamo customer_id, lo aggiorniamo (email/name/address).
    Altrimenti creiamo un nuovo Customer via /admin/customers.
    """
    if customer.customer_id:
        url = f"{API_BASE}/admin/customers/{customer.customer_id}"
        body = {
            "email": customer.email,
            "name": customer.name,
            "metadata": {"internal_customer_ref": customer.internal_customer_ref} if customer.internal_customer_ref else {},
        }
        if customer.address:
            body["address"] = customer.address.dict()
        r = requests.post(url, headers={**ADMIN_HEADERS, "Idempotency-Key": f"{uuid.uuid4()}:admin.customer.update"}, data=json.dumps(body), timeout=30)
        if r.status_code >= 300:
            raise RuntimeError(f"Update customer failed: {r.status_code} {r.text}")
        return customer.customer_id

    # Create
    create_url = f"{API_BASE}/admin/customers"
    body = {
        "email": customer.email,
        "name": customer.name,
        "metadata": {"internal_customer_ref": customer.internal_customer_ref} if customer.internal_customer_ref else {},
    }
    if customer.address:
        body["address"] = customer.address.dict()
    r = requests.post(create_url, headers={**ADMIN_HEADERS, "Idempotency-Key": f"{uuid.uuid4()}:admin.customer.create"}, data=json.dumps(body), timeout=30)
    if r.status_code >= 300:
        raise RuntimeError(f"Create customer failed: {r.status_code} {r.text}")
    return r.json().get("id")

def create_checkout_for_config(config: PlanConfiguratorInput) -> Dict[str, Any]:
    """
    Orchestrazione:
      1) pricing = compute_pricing(config)
      2) ensure_customer -> customer_id
      3) compone payload per /plans/checkout
         - Variante A: per-seat -> Price per-seat e quantity=seats (+ opzionale flat come secondo Price: richiederebbe estendere l'API per multi line_items)
         - Variante B: flat unico -> tutto in unit_amount, quantity=1
      4) chiama /plans/checkout (crea Product+Price e Session) e ritorna la URL
    """
    pricing = compute_pricing(config)
    customer_id = ensure_customer(config.customer_hint)

    # Metadati utili (verranno copiati sulla Subscription)
    sub_metadata = {
        "internal_customer_ref": config.customer_hint.internal_customer_ref or "",
        "plan_name": config.plan_name,
        "plan_fingerprint": _plan_fingerprint(config),
        "strategy": pricing.strategy,
    }

    # Strategy A: per-seat (raccomandata per team). 
    # Qui generiamo UN price per-seat. 
    # NOTA: il flat_monthly (addon/sla) richiederebbe una seconda riga in Checkout; 
    #       per semplicità, nel primo step puoi inglobarlo nel prezzo per-seat (ripartito).
    #       Esempio: ripartizione flat per-seat:
    if pricing.strategy == "per_seat" and pricing.flat_monthly_cents > 0 and pricing.seat_quantity > 0:
        # ripartizione arrotondata: aggiungiamo una quota flat per-seat
        extra_per_seat = Decimal(pricing.flat_monthly_cents) / Decimal(pricing.seat_quantity)
        extra_per_seat = int(extra_per_seat.to_integral_value(rounding=decimal.ROUND_HALF_UP))
        unit_amount_cents = pricing.unit_amount_cents_per_seat + extra_per_seat
    else:
        unit_amount_cents = pricing.unit_amount_cents_per_seat

    body = {
        "success_url": SUCCESS_URL,
        "cancel_url":  CANCEL_URL,
        "plan": {
            "product_name": config.plan_name,
            "currency": pricing.currency,
            "unit_amount": unit_amount_cents,  # in centesimi
            "recurring": {
                "interval": config.billing_cycle.interval,
                "interval_count": config.billing_cycle.interval_count,
                "usage_type": "licensed"
            },
            "trial_period_days": config.trial_days or None,
            "metadata": {
                "cfg_plan_fingerprint": _plan_fingerprint(config),
                "cfg_plan_name": config.plan_name
            }
        },
        "quantity": pricing.seat_quantity,
        "customer": {
            "customer_id": customer_id,
            "internal_customer_ref": config.customer_hint.internal_customer_ref
        },
        "client_reference_id": config.customer_hint.internal_customer_ref,
        "allow_promotion_codes": config.ui_options.allow_promo_codes,
        "automatic_tax": {"enabled": True},
        "tax_id_collection": {"enabled": bool(config.ui_options.collect_tax_id)},
        "billing_address_collection": config.ui_options.collect_billing_address,
        "subscription_metadata": sub_metadata
    }

    # Chiamata alla tua API
    url = f"{API_BASE}/plans/checkout"
    headers = {**USER_HEADERS, "Idempotency-Key": f"{uuid.uuid4()}:plans.checkout.create"}
    r = requests.post(url, headers=headers, data=json.dumps(body), timeout=40)
    if r.status_code >= 300:
        raise RuntimeError(f"Checkout create failed: {r.status_code} {r.text}")
    return r.json()

def _plan_fingerprint(config: PlanConfiguratorInput) -> str:
    """
    Crea un fingerprint stabile della config per deduplicare Price/riuso (se vuoi).
    In un sistema reale potresti salvarlo in DB -> price_id cache.
    """
    j = json.dumps(config.model_dump(), sort_keys=True, ensure_ascii=False)
    import hashlib
    return hashlib.sha256(j.encode("utf-8")).hexdigest()[:16]
```

### Come usarlo (esempio)

```python
# run_configurator_example.py
from services.plan_configurator import (
    PlanConfiguratorInput, BillingCycle, Features, AddOn, CustomerHint, Address, UIOptions,
    create_checkout_for_config
)

cfg = PlanConfiguratorInput(
    plan_name="AI Workspace Custom",
    currency="eur",
    billing_cycle=BillingCycle(interval="month", interval_count=1),
    seats=12,
    features=Features(ai_gpu_minutes=5000, storage_gb=200, sla="premium", chat_history_retention_days=90),
    addons=[AddOn(key="priority_support", quantity=1)],
    trial_days=7,
    customer_hint=CustomerHint(
        customer_id=None,
        email="mario.rossi@example.com",
        name="Mario Rossi",
        internal_customer_ref="user-42",
        address=Address(line1="Via Roma 1", city="Milano", postal_code="20100", country="IT")
    ),
    ui_options=UIOptions(allow_promo_codes=True, collect_tax_id=True, collect_billing_address="auto")
)

res = create_checkout_for_config(cfg)
print("Checkout Session:", res.get("id"))
print("Checkout URL:", res.get("url"))
print("Customer:", res.get("customer_id"))
```

---

# 4) Pattern architetturale consigliato (dinamica piani)

1. **Frontend** invia JSON di configurazione “alto livello” (no prezzi!).
2. **Backend** (questo orchestratore):

   * **valida** e **normalizza** i parametri;
   * **calcola** prezzi con un **pricing engine server-side** ( `Decimal`, rounding corretto, nessuna fiducia sul client );
   * produce un **fingerprint** della configurazione (hash) per:

     * cercare se c’è già un **Price** creato per quella config (cache DB: fingerprint → `price_id`);
     * altrimenti **creare** Product/Price (lo fa `/plans/checkout` usando i dati `plan`).
   * **risolve/crea** il **Customer** e garantisce **indirizzo valido** se usi `automatic_tax`.
   * crea la **Checkout Session** e **ritorna l’URL**.
3. **Webhook**: su `checkout.session.completed` salva in DB:

   * `customer_id`, `subscription_id`, `client_reference_id`, `plan_fingerprint`
   * eventuale `portal_url` generata on-demand quando serve
4. **Portal**: quando l’utente vuole gestire l’abbonamento/metodi, chiedi al backend di generare un **Portal Session** via `/plans/portal/session`.

> **Caching “price explosion”**: se i piani sono molto variabili, rischi di creare migliaia di Prices. Usa una **tabella cache** per riusare `price_id` per config identiche. In alternativa, mantieni un **catalogo** di 10–20 combinazioni (lookup\_key) e applica “moltiplicatori” via `quantity` (es. per-seat).

---

# 5) Varianti utili

* **Prezzo flat unico**
  Somma tutto (base+add-on+sla), `quantity=1`. Sostituisci nel composer:

  ```python
  unit_amount_cents = total_flat_cents
  quantity = 1
  usage_type="licensed"
  ```

* **Metered add-on** (usage-based)
  Compra la subscription metered in Checkout (price con `usage_type="metered"`), poi **reporti i consumi** con `usage_records.create` sul `subscription_item` via webhook/cron. È un flusso più avanzato: tieni separate le linee metered (potrebbe richiedere estendere la tua rotta per multi-line).

* **Multi-currency**
  Mappa `currency` → listino dedicato, evita conversioni runtime. Se proprio devi convertire, **pinna il tasso** per sessioni brevi e arrotonda bene.

* **Idempotenza**
  Chiave **diversa** per ogni POST (noi usiamo `uuid4():operazione`). Non riutilizzare la stessa tra endpoint distinti.

* **Metadati**
  Salva sempre:

  * `internal_customer_ref` (utente interno)
  * `plan_fingerprint` e `plan_name`
    Così nei webhook riconcili tutti i flussi senza ambiguità.

---

# 6) Errori comuni & come evitarli

* **Automatic tax**: Customer **senza indirizzo** → crea/aggiorna Customer **prima** della Checkout.
* **Tax ID collection**: se abilitata, Stripe può richiedere che il **name** del Customer sia aggiornabile → se non lo imposti tu, valuta (in un’estensione futura) `customer_update={"name":"auto","address":"auto"}` nella Session.
* **Portal 400**: non hai salvato la **Default configuration** in test mode → vai in Dashboard → Customer Portal → **Save**.
* **Idempotency cross-endpoint**: non usare la stessa chiave tra `customers`, `products`, `prices`, `checkout.sessions`.

---

## Conclusione

Con questo **configuratore**:

* ricevi **parametri funzionali** (seats, storage, SLA, addons),
* **calcoli** prezzi server-side (compliance, coerenza, audit),
* **orchestri** le tue rotte (`/admin/customers`, `/plans/checkout`) in modo robusto (idempotenza, metadata, address, automatic\_tax),
* **restituisci l’URL** di Checkout e tracci tutto via webhook,
* abiliti un **backend scalabile** per **piani dinamici** lato utente, senza esporre logiche di prezzo nel client.