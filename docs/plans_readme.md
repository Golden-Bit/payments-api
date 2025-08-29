# Report completo: Setup Stripe, Demo End-to-End, API, Webhook e Billing Portal

---

## 0) Prerequisiti e Struttura progetto

**Stack tecnico:**

* Python 3.11+
* FastAPI + stripe-python + uvicorn
* Stripe CLI
* File `.env` per API e demo

**Struttura directory (riassunto):**

```
app/
  main.py
  config.py
  security.py
  stripe_client.py
  utils/errors.py
  routers/
    user.py
    admin.py
    proxy.py
    webhooks.py
    plans.py
demo_subscription_flow.py     # script demo con webhook su :9000
.env                          # variabili ambiente della TUA API
```

---

## 1) Installazione Stripe CLI

### Windows (con Scoop, consigliato)

1. **Installa Scoop** (da PowerShell utente, non admin):

   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   iwr get.scoop.sh -useb | iex
   ```
2. **Installa Stripe CLI**:

   ```powershell
   scoop install stripe
   stripe version
   ```

### Windows (manuale)

1. Scarica ZIP da GitHub (Stripe CLI Releases).
2. Scompatta in `C:\stripe-cli\`.
3. Aggiungi al **PATH** tramite Pannello di Controllo → Variabili d’ambiente.
4. Verifica:

   ```powershell
   stripe version
   ```

### macOS

```bash
brew install stripe/stripe-cli/stripe
stripe version
```

### Linux

```bash
curl -fsSL https://cli.stripe.com/install.sh | bash
stripe version
```

---

## 2) Setup da Dashboard Stripe (Test mode)

1. Attiva **“View test data”** in alto a sinistra.
2. Copia la tua `sk_test_…` in `.env` della TUA API.
3. (Opzionale) Pinna la versione API (`STRIPE_API_VERSION`).
4. **Configura il Customer Portal**:

   * Vai su Settings → **Billing → Customer Portal**.
   * Premi **Save** anche senza modificare nulla → verrà creata la configurazione di default.
5. Abilita metodi di pagamento e tassazione in **Test mode** se vuoi provarli.

---

## 3) Configurazione `.env`

### `.env` API

```dotenv
API_KEYS=adminkey123:admin,userkey456:user
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
STRIPE_API_VERSION=2025-07-30.basil
ALLOW_TEST_MODE=true
```

### `.env` demo

```dotenv
API_BASE=http://localhost:8000
ADMIN_API_KEY=adminkey123
USER_API_KEY=userkey456
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
RETURN_URL=https://tuo-sito.com/account
```

---

## 4) Avvio ambienti

1. **API FastAPI**

   ```bash
   uvicorn app.main:app --reload
   ```

   Ascolta su `http://localhost:8000/`

2. **Stripe CLI (webhook forwarding)**

   ```bash
   stripe listen --forward-to localhost:9000/webhooks/stripe
   ```

   Copia `whsec_...` in `.env` demo.

3. **Script demo**

   ```bash
   python demo_subscription_flow.py
   ```

   * Crea o aggiorna un Customer con indirizzo valido.
   * Crea una Checkout Session.
   * Avvia un webhook server su `:9000`.
   * Salva eventi in `webhook_events.jsonl`.

---

## 5) Rotte principali (API)

* **/plans/checkout (POST)**: crea Checkout Session (subscription).
* **/plans/portal/session (POST)**: genera URL Billing Portal.
* **/plans/customers/{id}/subscriptions (GET)**: lista abbonamenti di un Customer.
* **/plans/subscriptions/{id}/cancel (POST)**: cancella un abbonamento.
* **/plans/subscriptions/{id}/pause/resume (POST)**: sospendi/riprendi abbonamento.
* **/plans/customers/{id}/payment-methods (GET)**: lista metodi di pagamento.
* **/plans/customers/payment-methods/attach (POST)**: collega Payment Method a Customer.
* **/admin/customers (POST)**: crea Customer con indirizzo valido.
* **/admin/customers/{id} (POST)**: aggiorna Customer.

---

## 6) Script demo (flow)

1. Avvia webhook server su `:9000`.
2. Crea/aggiorna un Customer (con indirizzo).
3. Crea Checkout Session e stampa URL.
4. Al `checkout.session.completed`:

   * verifica firma
   * scrive su file JSONL
   * crea Billing Portal link via API

---

## 7) Billing Portal – configurazione e uso

### 7.1 Configurazione su Dashboard

1. Vai in **Settings → Billing → Customer Portal**.
2. In modalità **Test**, premi **Save** (obbligatorio: altrimenti errori 400).
3. Puoi personalizzare:

   * Funzionalità abilitate (aggiornamento piani, cancellazione, pagamento fatture).
   * Branding (logo, colori).
   * Policy (es. disabilitare cancellazione).

Ogni volta che premi **Save**, Stripe salva una **configuration** (`pc_...`).
Se non ne passi una all’API, viene usata quella **default** di test.

---

### 7.2 Creare Portal Session via API

Chiamata diretta alla tua API:

```bash
curl -X POST http://localhost:8000/plans/portal/session \
  -H "X-API-Key: userkey456" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "cus_123",
    "return_url": "https://tuo-sito.com/account"
  }'
```

Risposta:

```json
{ "id": "bps_123", "url": "https://billing.stripe.com/p/session/..." }
```

### 7.3 Deep-link Portal

Puoi far atterrare l’utente su azioni specifiche:

```json
{
  "customer_id": "cus_123",
  "return_url": "https://tuo-sito.com/account",
  "flow_data": { "type": "payment_method_update" }
}
```

`flow_data.type` può essere:

* `payment_method_update`
* `subscription_update`
* `subscription_cancel`

---

### 7.4 Uso pratico lato utente

* Quando un utente apre la tua app, recuperi il suo `customer_id` (o cerchi tramite metadata `internal_customer_ref`).
* Chiami `/plans/portal/session` e ottieni la URL.
* Mostri o reindirizzi l’utente a quella URL.
* L’utente gestisce da solo abbonamenti, carte, fatture.

> ⚠️ L’URL del Portal è temporaneo (di solito valido per qualche minuto).
> Quindi va generato **on demand** ogni volta che serve.

---

## 8) Troubleshooting principali

* **Idempotency error**: usa chiavi diverse per endpoint.
* **Automatic tax error**: Customer senza indirizzo → aggiorna prima di Checkout.
* **Tax ID collection error**: aggiungi `"customer_update": {"address": "auto", "name": "auto"}` o valorizza già il nome.
* **Portal error**: devi **salvare la configurazione** in Dashboard Test.
* **subscription\_id null**: patcha handler webhook (`customer.subscription.created` → prendi `obj["id"]`).
* **.env non aggiornato**: riavvia processi, controlla path.

---

## 9) Sequenza test consigliata

1. Avvia API (`uvicorn app.main:app --reload`).
2. Stripe CLI:

   ```bash
   stripe listen --forward-to localhost:9000/webhooks/stripe
   ```
3. Dashboard → Configura Customer Portal (Test) → Save.
4. Script demo:

   ```bash
   python demo_subscription_flow.py
   ```
5. Completa pagamento con carta test `4242 4242 4242 4242`.
6. Controlla `webhook_events.jsonl`:

   * eventi come `checkout.session.completed`, `invoice.paid`, `portal_url`.

---

## 10) Riassunto “dietro le quinte”

* La tua API gestisce Customer, Product, Price, Subscription, Portal.
* Lo script demo orchestra: Customer → Checkout → Webhook → Portal.
* Stripe CLI inoltra eventi al webhook locale.
* Dashboard mostra tutto in **Test mode**.
* Nessun addebito reale avviene.
