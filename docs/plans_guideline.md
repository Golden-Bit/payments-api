Fantastico — ecco una **guida pratica e completa** per implementare, su una web-app, tutto il ciclo “piani & abbonamenti” sfruttando:

* **la tua API FastAPI** (`/plans/*`, `/admin/*`);
* la **UI ospitata da Stripe** (Checkout + Billing Portal);
* una **UI personalizzata** (React/Flutter) quando serve.

L’obiettivo: **configurazione dinamica** del piano, **pagamento**, **stato abbonamento**, **storico fatture**, **metodi di pagamento**, **annullamento/pausa/upgrade** e **pagina di selezione piani** (con toggle mensile/annuale) evitando acquisti duplicati.

---

# A) Architetture possibili (e quando sceglierle)

## A1) “Hosted-first” (consigliato per velocità e compliance)

* **Checkout**: Stripe **Checkout Session** (UI ospitata).
* **Gestione post-vendita**: **Billing Portal** (UI ospitata).
* **Config dinamica**: UI tua (React/Flutter) → invia JSON al tuo backend → il **backend calcola** prezzo e chiama `/plans/checkout`.
* **Pro**: minore sforzo, PCI ridotto, funzioni self-service già pronte (aggiorna PM, scarico fatture, cambio piano).
* **Contro**: meno controllo pixel-perfect sul flusso pagamento/gestione.

## A2) “Ibrido” (consigliato per app mature)

* **Config UI** totalmente tua; **Checkout** e **Portal** ospitati Stripe.
* In futuro, dove serve, aggiungi UI custom (es. pagina fatture “read-only” tua, ma per azioni complesse rimandi al Portal).

## A3) “Full custom payments UI”

* **Payment Element / Elements** (tutto nella tua UI).
* **Sconsigliato** se non strettamente necessario: più sforzo, oneri PCI, devi coprire tu tutte le varianti.
* Mantiene senso per esigenze di **UX completamente custom** o metodi particolari non supportati da Checkout.

> In tutti i casi: mantieni **logica prezzi** e **controlli** **solo** lato backend. Il client passa parametri “funzionali” (seats, storage…), non importi.

---

# B) Flussi end-to-end consigliati

## B1) Configurazione dinamica del piano (frontend → backend)

1. **UI tua (React/Flutter)**: form con **seats**, **storage**, **SLA**, add-on, **toggle mensile/annuale**.
2. Chiami un **endpoint backend** (es. `/orchestrator/checkout`) passando **solo** la configurazione **non-prezzata**.
3. Il **backend**:

   * valida input;
   * **calcola il prezzo** (Decimal, arrotondamento ai cent);
   * **associa/crea Customer** (indirizzo valido → `automatic_tax`);
   * crea **Checkout Session** via `/plans/checkout` (o, se hai `price_id` predefiniti, li riusa);
   * ritorna **`url`** di Checkout.
4. Il frontend fa **redirect** all’URL di Checkout.

> Nota: se vuoi visualizzare un “**prezzo stimato**” prima del redirect, il backend può esporre anche un endpoint **preview** che restituisce solo il calcolo.

## B2) Pagamento in Checkout (ospitato)

* L’utente paga su Stripe.
* Stripe invia i **webhook**; il tuo listener:

  * verifica la firma,
  * salva in DB `customer_id`, `subscription_id`, `plan_fingerprint`, `price_id/product_id`,
  * opzionale: **crea subito un link Portal** e lo salva.

## B3) Gestione post-vendita (Portal vs UI tua)

* **Portale Stripe** (consigliato): crea un link via `/plans/portal/session` e reindirizza l’utente.
  Lì potrà:

  * cambiare metodo di pagamento,
  * vedere e scaricare fatture,
  * **cancellare** (subito o fine periodo),
  * **aggiornare piano** (se abiliti “Allow plan changes” in Portal).
* **UI tua** (solo dove serve):
  *Read-only* (stato, prossimo rinnovo, storico) via le tue rotte `/plans/customers/{cus}/subscriptions`, `/invoices`, …
  Per azioni **mutanti**, se non vuoi gestire tutti gli edge case, **rimanda** al Portal.

---

# C) Pagina “Piani” (preconfigurati o configurabili)

## C1) Catalogo preconfigurato (semplice)

* **Un Product** con **2 Prices**: `mensile` e `annuale` (scontato).
* UI: card piani con **toggle** “mensile/annuale”.
* “Acquista” → backend chiama `/plans/checkout` **con `price_id`** corrispondente.
* Evita duplicazioni: vedi **Sezione G**.

## C2) Piano **dinamico** (configuratore)

* UI: slider seats, storage, add-on, toggle billing.
* “Calcola prezzo”: chiama backend “preview”.
* “Acquista”: chiama backend orchestratore che **crea un Price on-the-fly** (o riusa un `price_id` da cache se stessa config), e poi la **Checkout Session**.

---

# D) Esempi UI (snippet)

## D1) React — chiamare la tua API per Checkout

```jsx
// PlanCard.jsx (bozza)
import React, { useState } from "react";

export default function PlanCard({ defaultSeats = 5 }) {
  const [seats, setSeats] = useState(defaultSeats);
  const [billing, setBilling] = useState("month"); // "month" | "year"

  async function handleBuy() {
    const cfg = {
      plan_name: "AI Workspace Custom",
      currency: "eur",
      billing_cycle: { interval: billing, interval_count: 1 },
      seats,
      features: { ai_gpu_minutes: 3000, storage_gb: 100, sla: "standard", chat_history_retention_days: 30 },
      addons: [],
      trial_days: 7,
      customer_hint: { email: "mario.rossi@example.com", name: "Mario Rossi", internal_customer_ref: "user-42",
        address: { line1: "Via Roma 1", city: "Milano", postal_code: "20100", country: "IT" } },
      ui_options: { allow_promo_codes: true, collect_tax_id: true, collect_billing_address: "auto" }
    };

    const res = await fetch("/orchestrator/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cfg)
    });
    if (!res.ok) {
      const t = await res.text();
      alert("Errore: " + t);
      return;
    }
    const data = await res.json();
    window.location.href = data.url; // redirect a Stripe Checkout
  }

  return (
    <div>
      <h3>AI Workspace</h3>
      <label>Seats: <input type="number" min={1} value={seats} onChange={e => setSeats(+e.target.value)} /></label>
      <div>
        <label>
          <input type="radio" name="bill" checked={billing==="month"} onChange={()=>setBilling("month")} />
          Mensile
        </label>
        <label>
          <input type="radio" name="bill" checked={billing==="year"} onChange={()=>setBilling("year")} />
          Annuale
        </label>
      </div>
      <button onClick={handleBuy}>Acquista</button>
    </div>
  );
}
```

## D2) Flutter (web o desktop) — aprire Checkout

```dart
// Usa url_launcher per aprire la URL della sessione
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;

class BuyButton extends StatelessWidget {
  const BuyButton({super.key});

  Future<void> _buy() async {
    final cfg = {
      "plan_name": "AI Workspace Custom",
      "currency": "eur",
      "billing_cycle": {"interval": "month", "interval_count": 1},
      "seats": 10,
      "features": {"ai_gpu_minutes": 3000, "storage_gb": 100, "sla": "standard", "chat_history_retention_days": 30},
      "addons": [],
      "trial_days": 7,
      "customer_hint": {
        "email": "mario.rossi@example.com",
        "name": "Mario Rossi",
        "internal_customer_ref": "user-42",
        "address": {"line1": "Via Roma 1", "city": "Milano", "postal_code": "20100", "country": "IT"}
      },
      "ui_options": {"allow_promo_codes": true, "collect_tax_id": true, "collect_billing_address": "auto"}
    };

    final res = await http.post(
      Uri.parse("https://tuo-backend.example.com/orchestrator/checkout"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode(cfg),
    );

    if (res.statusCode >= 300) {
      debugPrint("Errore: ${res.body}");
      return;
    }
    final data = jsonDecode(res.body);
    final url = data["url"];
    if (url != null && await canLaunchUrl(Uri.parse(url))) {
      await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(onPressed: _buy, child: const Text("Acquista"));
  }
}
```

> In entrambi i casi, **non** passare importi dal client. Lascia che il server calcoli e crei la Session.

---

# E) Stato abbonamento, fatture, metodi, azioni

## E1) “Pagina Account Billing” (UI tua + Portal)

* **Read-only** (UI tua):

  * stato abbonamento corrente (active/past\_due/trialing…),
  * prossimo rinnovo (`current_period_end`),
  * **storico fatture** (numero, data, importo, link PDF),
  * PM di default (ultime 4 cifre, brand).
* **Azioni** (rimanda al **Portal**):

  * **modifica metodo di pagamento**,
  * **upgrade/downgrade**,
  * **cancella** (immediata o fine periodo),
  * **pausa/riprendi**.

### Come implementare (server)

* Prevedi un endpoint **“me”** per non esporre `cus_` al client:

  ```python
  # /me/billing (esempio)
  # return: { customer_id, subscriptions[], invoices[], payment_methods[], portal_url }
  ```

  Il backend ricava `customer_id` dal tuo DB (mapping user↔customer), chiama le **rotte /plans** già presenti e compone la risposta.
* Quando l’utente clicca “Gestisci abbonamento”, il client chiama `/plans/portal/session` e fa redirect all’URL ottenuto.

---

# F) Upgrade/Downgrade/Annullamento/Pausa

## F1) Con **Billing Portal** (consigliato)

* Dashboard → **Customer Portal settings**: abilita “**Allow plan changes**”, “**Allow cancel**”, “**Allow update payment methods**”, ecc.
* Da backend: crea **Portal Session** con:

  ```json
  { "customer_id": "cus_xxx", "return_url": "https://app.tuo.com/billing" }
  ```
* (Opzione avanzata) **Deep link** a una Subscription specifica (flow\_data).
  Se non ti serve, l’entry standard del Portal è ottima: l’utente vede tutte le sue subscription e agisce.

## F2) Con **API tue** (UI personalizzata)

* Usa le rotte:

  * `POST /plans/subscriptions/{sub}/cancel` (ora o fine periodo),
  * `POST /plans/subscriptions/{sub}/pause`,
  * `POST /plans/subscriptions/{sub}/resume`,
  * Update PM: `POST /plans/customers/payment-methods/attach`.
* **Upgrade/downgrade** manuale:

  * recuperi subscription,
  * **modifichi** il `subscription_item` con un altro `price_id`,
  * imposti `proration_behavior` come preferisci (prorata/fattura/subito/none).
    *Nota*: La tua rotta attuale non espone l’update dell’item; puoi aggiungerla o usare **Portal**.

---

# G) Evitare che l’utente acquisti due volte lo stesso piano

## G1) Guard server-side **prima** del Checkout (consigliato)

Nel tuo orchestratore (o in `/plans/checkout`), **prima** di creare la Session:

1. Risolvi il **customer\_id**.
2. `stripe.Subscription.list(customer=..., status='active')`
3. Verifica se c’è già una subscription **equivalente** (stesso `plan_fingerprint` in `subscription.metadata` **oppure** stesso `product_id` + stessa cadenza + stesso “tenant”).
4. Se sì, **blocca** la creazione della Session e ritorna un **409** con messaggio: “Hai già questo piano attivo”.

> Hai già `subscription_metadata` con `internal_customer_ref` e puoi aggiungere `plan_fingerprint`. Questo rende il check banale.

### Pseudocodice

```python
def guard_no_duplicate(customer_id, plan_fingerprint):
    subs = stripe.Subscription.list(customer=customer_id, status="active", limit=20)
    for s in subs.auto_paging_iter():
        if (s.metadata or {}).get("plan_fingerprint") == plan_fingerprint:
            raise HTTPException(status_code=409, detail="Piano già attivo")
```

## G2) Lock sulle “Session in corso”

* Crea una tabella `checkout_sessions` con (user\_id, plan\_fingerprint, created\_at, status: pending|completed|expired).
* Quando crei una nuova Session per lo stesso utente e stesso fingerprint **entro N minuti**, rifiuta o riusa la precedente.
* Usa **Idempotency-Key** per evitare doppi POST se l’utente “spamma” il bottone.

## G3) UX lato client

* Disabilita il bottone “Acquista” se la pagina “Account Billing” ti dice che il piano è già attivo.
* Se l’utente torna alla pagina piani dopo pochi secondi, mostra il banner “Pagamento in corso…”.

---

# H) Toggle **mensile/annuale** (consigli pratici)

* Mantieni **due Price** distinti sullo **stesso Product** (mensile e annuale).
* **Mostra** risparmio “2 mesi gratis” sull’annuale, ma **non** calcolare live i 12× sul client; è una **proprietà commerciale** tua, non di Stripe.
* Se usi **configuratore dinamico**:

  * calcola **due** prezzi nel backend e lascia alla UI solo il **toggle** (il payload che mandi a `/plans/checkout` conterrà la scelta).

---

# I) Dati e storage (DB consigliato)

Tabelle minime:

* `users` → `id`, `stripe_customer_id`, `internal_customer_ref`
* `subscriptions_cache` → `user_id`, `stripe_subscription_id`, `status`, `current_period_end`, `plan_fingerprint`, `product_id`, `price_id`
* `checkout_sessions` → `session_id`, `user_id`, `plan_fingerprint`, `status`, `created_at`
* `webhook_events` → `id`, `type`, `payload`, `processed_at`

Regole:

* **Fonte di verità** = Stripe (webhook). Il DB serve per **cache/UX**.
* Aggiorna cache su `customer.subscription.*`, `invoice.*`, `checkout.session.completed`.

---

# L) Sicurezza & robustezza

* **Mai** fidarsi di importi lato client.
* **Verifica firma** dei webhook (`whsec_…`).
* **Idempotency**: chiavi **diverse per ogni POST** (niente riuso cross-endpoint).
* **Non** esporre `cus_…` al client: esponi **solo** endpoint “me”.
* **Automatic Tax**: il Customer deve avere indirizzo **valido** *prima* del Checkout, oppure usa `customer_update[address]=auto` (se estendi la rotta).
* **Portal** in Test: **salva** la configurazione in Dashboard Test (altrimenti 400).

---

# M) Rotte chiave della tua API (ripasso “cosa usare, quando”)

* **Creazione Checkout**: `POST /plans/checkout`

  * Con `price_id` (catalogo fissi) **oppure** con `plan{…}` (dinamico).
  * Passa `customer.customer_id` (creato/aggiornato prima) e `subscription_metadata` con `plan_fingerprint`, `internal_customer_ref`.

* **Portal**: `POST /plans/portal/session`

  * Input minimo: `customer_id`, `return_url`.
  * **Prerequisito:** Portal configurato in Dashboard Test **(Save)**.

* **Stato & storico**:

  * `GET /plans/customers/{cus}/subscriptions`
  * `GET /plans/customers/{cus}/invoices`
  * `GET /plans/customers/{cus}/payment-methods`

* **Azioni**:

  * `POST /plans/subscriptions/{sub}/cancel`
  * `POST /plans/subscriptions/{sub}/pause`
  * `POST /plans/subscriptions/{sub}/resume`
  * `POST /plans/customers/payment-methods/attach`

> Per UX sicura, aggiungi endpoint “**/me/billing**” che incapsula le chiamate sopra e nasconde `cus_…` al client.

---

# N) Esempio: endpoint orchestratore lato backend

Se non lo hai già, crea un **endpoint unico** per la tua UI:

```python
# app/routers/orchestrator.py (bozza)
from fastapi import APIRouter, Depends, Body, HTTPException, Request
from ..security import require_user_or_admin, Principal
import requests, uuid, json

router = APIRouter(prefix="/orchestrator", tags=["orchestrator"])

@router.post("/checkout")
def orchestrate_checkout(p: Principal = Depends(require_user_or_admin), payload: dict = Body(...)):
    """
    Riceve configurazione piano (no importi!), calcola prezzo e chiama /plans/checkout.
    Qui puoi:
      - validare input
      - calcolare prezzi (riusa il pricing engine che ti ho fornito)
      - garantire NO duplicati per lo stesso piano/utente
      - creare/aggiornare Customer via /admin/customers
    Ritorna: { url, id, customer_id }
    """
    # 1) compute price (usa il tuo servizio pricing) ...
    # 2) ensure customer ...
    # 3) guard_no_duplicate ...
    # 4) POST /plans/checkout con Idempotency-Key dedicata
    # 5) return response
    ...
```

---

# O) Checklist operativa

1. **Dashboard Test**: salva **Customer Portal** (se no 400).
2. **CLI**: `stripe listen --forward-to localhost:9000/webhooks/stripe`, copia `whsec_…` nello script.
3. **.env**: ricarica processi ogni volta che cambi chiavi.
4. **Customer**: crea/aggiorna **con indirizzo valido** se usi `automatic_tax`.
5. **Idempotency**: sempre una chiave **per singola POST**.
6. **No duplicati**: controlla subscription attive **prima** della Checkout.
7. **Webhooks**: salva cache e audit; logga errori; non bloccare su eccezioni non critiche.

---

Se vuoi, posso prepararti:

* un **endpoint `/me/billing`** pronto all’uso,
* un **pricing engine** con **cache `price_id`** (fingerprint→price) per non creare migliaia di Prices,
* esempi **React** completi (pagine Piani/Account) e un **widget Flutter** riutilizzabile.
