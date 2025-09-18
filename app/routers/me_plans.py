# app/routers/me_plans.py
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Optional, Literal, Dict, Any, List
from datetime import datetime, timezone
import stripe
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, status, Security
from pydantic import BaseModel, Field, EmailStr
from .utils.plans_utils import _require_bearer_token, _verify_and_get_user, _base_idem_from_request, _opts_from_request, \
    _get_or_ensure_customer_id_cached, _idem, _raise_from_stripe_error, \
    CancelRequest, PauseRequest, ResumeRequest, AttachMeRequest, _create_price_from_dynamic_request, \
    DynamicCheckoutRequest, _ensure_subscription_ownership, _parse_resources_json, _compute_remaining, _require_api_key, \
    _to_map, _to_list, _assert_not_exceed, ConsumeResourcesRequest, SetResourcesRequest, PLAN_POLICIES, \
    _validate_return_url, _maybe_rollover_resources_stripe_aligned, _assert_set_constraints, \
    _assert_consume_constraints, PLAN_VARIANTS, _ensure_price_for_variant, _sync_subscription_variant_state, \
    _infer_period_bounds, ensure_portal_configuration, _resolve_portal_configuration_id, \
    PortalFeaturesOverride, PortalCancelDeepLinkRequest, PortalUpdateDeepLinkRequest, BusinessProfileOverride, \
    PortalConfigSelector, _find_alive_subscription_id_for_customer, PortalSessionRequest, PortalUpgradeDeepLinkRequest, \
    _fast_sync_and_rollover_in_memory
from ..security import require_jwt_user, optional_stripe_connect_account, optional_idempotency_key, \
    require_admin_api_key


# Se riusi helper/costrutti dal router /plans, puoi importarli direttamente
# oppure incollarne una copia qui. Qui li reimplementiamo in modo minimale e sicuro per “ME”.

router = APIRouter(
    prefix="/me/plans",
    tags=["me-plans-subscriptions"],
    responses={
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized (token mancante/invalid)"},
        403: {"description": "Forbidden"},
        429: {"description": "Rate limited by Stripe"},
        500: {"description": "Errore interno"},
    },
    dependencies=[
        Security(require_jwt_user),
        Security(optional_stripe_connect_account),
        Security(optional_idempotency_key),
    ],
)
# =============================================================================
#                                  ENDPOINTS “ME”
# =============================================================================
@router.post(
    "/checkout",
    summary="Crea la Checkout Session (piano dinamico o variante catalogo) e restituisce l'URL",
)
def me_create_checkout(
    request: Request,
    payload: DynamicCheckoutRequest = Body(...),
):
    """
    Supporta due modalità alternative:
      A) VARIANT-FIRST: payload.variant = {free|base|pro}_{monthly|annual}
         - Provisioning/riuso Product/Price per la variante (senza duplicare inutilmente).
         - Risorse base dal catalogo variante (base_resources), res_mode dalla variante/policy.
      B) DINAMICO: payload.pricing_method + payload.resources
         - Calcolo unit_amount e risorse iniziali lato server via registry.
         - Crea Product+Price secondo policy del plan_type.

    Metadati scritti sulla Subscription (comuni ai due flussi):
      - internal_customer_ref
      - plan_type
      - variant (solo flusso A)
      - pricing_method (variant_fixed per flusso A, altrimenti quello dinamico)
      - resources_requested_json (sempre stringa JSON; [] nel flusso A)
      - resources_provided_json (stato iniziale corrente)
      - base_resources_provided_json (dote per grant reset/add)
      - resources_used_json (sempre "[]")
      - res_mode, res_grant_interval, res_grant_interval_count (dalla policy/variante)
      - active_price_id, active_product_id (per detection upgrade/downgrade senza webhook)
    """
    # 0) Auth utente
    user = request.state.user
    access_token = request.state.access_token

    # 1) Idempotency & Stripe opts
    base_idem = _base_idem_from_request(request)
    opts = _opts_from_request(request)

    # 2) Policy lato server (obbligatoria)
    policy = PLAN_POLICIES.get(payload.plan_type)
    if not policy:
        raise HTTPException(status_code=400, detail=f"Policy non definita per plan_type='{payload.plan_type}'")

    # 3) Validazione success/cancel URL contro allowlist (evita open-redirect)
    success_url = _validate_return_url(payload.success_url)
    cancel_url  = _validate_return_url(payload.cancel_url)

    try:
        # 4) Customer per l'utente corrente
        customer_id = _get_or_ensure_customer_id_cached(
            user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
        )

        # ─────────────────────────────────────────────────────────────
        # 5) Calcola SUBITO il price_id (serve per eventuale server_switch)
        # ─────────────────────────────────────────────────────────────
        created_product_id: Optional[str] = None
        price_id: str
        calc = None  # usato solo nel flusso dinamico

        if payload.variant:
            price_id, created_product_id, _ = _ensure_price_for_variant(
                plan_type=payload.plan_type,
                variant=payload.variant,
                base_idem=base_idem,
                opts=opts,
                allow_fallback_equivalent_any=True,
                reactivate_if_inactive=True,
            )
        else:
            price_id, created_product_id, calc = _create_price_from_dynamic_request(payload, base_idem, opts)

        # ─────────────────────────────────────────────────────────────
        # 6) ENFORCE opzionale: massimo una subscription viva per utente (config per piano)
        #    - "block": 409
        #    - "portal_update": crea deep-link al Portal per aggiornare (pro-rata) → 409 con URL
        #    - "server_switch": switch immediato lato server con pro-rata → return immediato
        # ─────────────────────────────────────────────────────────────
        existing_sub_id = _find_alive_subscription_id_for_customer(customer_id, opts)
        behavior = (policy.get("enforce_single_subscription") or "portal_update").lower()

        if existing_sub_id:
            if behavior == "block":
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "single_subscription_enforced",
                        "message": "Esiste già una subscription viva per questo utente. Completa dal Portal o cancella quella corrente.",
                        "subscription_id": existing_sub_id,
                    },
                )


            # ─────────────────────────────────────────────────────────────
            # 6) ENFORCE: ramo "portal_update" — USA il selettore passato in input (se presente)
            # ─────────────────────────────────────────────────────────────
            elif behavior == "portal_update":
                # Se il client ha passato 'portal', usalo; altrimenti costruisci un default sensato.
                if payload.portal:
                    selector = payload.portal
                    # Se manca plan_type nel selettore ma lo conosciamo dal payload, valorizzalo
                    if not selector.plan_type:
                        selector.plan_type = payload.plan_type
                else:
                    # Fallback “compatibile”: se non viene passato nulla dal client,
                    # costruiamo un selettore default (prima deduce annual vs monthly dalla variant, se c’è)
                    selector = PortalConfigSelector(
                        configuration_id=None,
                        plan_type=payload.plan_type,
                        # puoi anche non passare portal_preset qui e usare direttamente le varianti
                        portal_preset=None,
                        # di default: se il client NON ha passato nulla, proponiamo almeno la variant target
                        # assieme ad alcune alternative “sorelle”. Qui metti quello che vuoi esporre.
                        variants_override=[
                            v for v in (
                                           [payload.variant] if payload.variant else []
                                       ) or ["base_monthly", "pro_monthly", "base_annual", "pro_annual"]
                        ],
                        features_override=PortalFeaturesOverride(
                            subscription_update={
                                "enabled": True,
                                "default_allowed_updates": ["price"],
                                "proration_behavior": "create_prorations",
                            },
                            payment_method_update={"enabled": True},
                            subscription_cancel={"enabled": True, "mode": "at_period_end"},
                        ),
                        business_profile_override=BusinessProfileOverride(
                            headline=f"{payload.plan_type} – Update plan"
                        ),
                    )

                config_id = _resolve_portal_configuration_id(selector=selector, base_idem=base_idem, opts=opts)

                portal = stripe.billing_portal.Session.create(
                    customer=customer_id,
                    return_url=success_url,  # puoi usare anche cancel_url o altro
                    configuration=config_id,
                    flow_data={"type": "subscription_update",
                              "subscription_update": {"subscription": existing_sub_id}},
                    **opts,
                )

                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "single_subscription_portal_redirect",
                        "message": "Aggiorna il piano esistente dal Billing Portal.",
                        "portal_url": portal["url"],
                        "subscription_id": existing_sub_id,
                        "configuration_id": config_id,
                    },
                )

            elif behavior == "server_switch":
                # Switch istantaneo lato server con pro-rata
                sub = stripe.Subscription.retrieve(existing_sub_id, expand=["items.data"], **opts)
                item = next((it for it in (sub.get("items", {}).get("data") or []) if not it.get("deleted")), None)
                if not item:
                    raise HTTPException(status_code=400, detail="Subscription priva di items aggiornabili.")

                updated = stripe.Subscription.modify(
                    existing_sub_id,
                    items=[{"id": item["id"], "price": price_id, "quantity": 1}],
                    proration_behavior="create_prorations",
                    cancel_at_period_end=False,
                    idempotency_key=_idem(base_idem, f"sub.switch.{existing_sub_id}.{price_id}"),
                    **opts,
                )
                # Allinea metadata/risorse
                _sync_subscription_variant_state(existing_sub_id, opts)
                return {
                    "switched": True,
                    "subscription_id": existing_sub_id,
                    "active_price_id": updated["items"]["data"][0]["price"]["id"],
                    "status": updated["status"],
                }

        # ─────────────────────────────────────────────────────────────
        # 7) Nessuna subscription viva → prosegui con Checkout (come prima)
        #    Prepara i metadata a seconda del flusso (variant vs dynamic)
        # ─────────────────────────────────────────────────────────────
        if payload.variant:
            # a) Dote risorse e res_mode per la variante/policy
            vconf = (PLAN_VARIANTS.get(payload.plan_type) or {}).get(payload.variant) or {}
            base_resources = vconf.get("base_resources") or []
            res_mode = str(vconf.get("res_mode") or policy.get("res_mode") or "reset")

            # b) Metadati risorse iniziali
            resources_requested_json = "[]"  # nessuna richiesta dal client in variante catalogo
            resources_provided_json = json.dumps(base_resources, separators=(",", ":"))
            resources_used_json = "[]"

            # c) Traccia price/product attivo per detection upgrade/downgrade
            active_price_id = price_id
            active_product_id = created_product_id

            # d) Metadata Subscription
            subscription_metadata: Dict[str, str] = {
                "internal_customer_ref": user["user_ref"],
                "plan_type": payload.plan_type,
                "variant": payload.variant,
                "pricing_method": "variant_fixed",
                "resources_requested_json": resources_requested_json,
                "resources_provided_json": resources_provided_json,
                "resources_used_json": resources_used_json,
                "base_resources_provided_json": resources_provided_json,
                "res_mode": res_mode,
                "res_grant_interval": str(policy.get("res_grant_interval") or "month"),
                "res_grant_interval_count": str(int(policy.get("res_grant_interval_count") or 1)),
                "active_price_id": active_price_id,
                "active_product_id": active_product_id or "",
            }
        else:
            # flusso DINAMICO (calc già disponibile)
            (
                _product_name,
                _unit_amount,
                _price_md,
                _product_md,
                _desc,
                resources_provided,  # List[DynamicResource]
            ) = calc

            resources_requested_json = json.dumps(
                [r.model_dump() for r in (payload.resources or [])],
                separators=(",", ":"),
            )
            resources_provided_json = json.dumps(
                [r.model_dump() for r in resources_provided],
                separators=(",", ":"),
            )
            resources_used_json = "[]"

            active_price_id = price_id
            active_product_id = created_product_id

            subscription_metadata: Dict[str, str] = {
                "internal_customer_ref": user["user_ref"],
                "plan_type": payload.plan_type,
                "pricing_method": payload.pricing_method or "",
                "resources_requested_json": resources_requested_json,
                "resources_provided_json": resources_provided_json,   # stato iniziale
                "resources_used_json": resources_used_json,           # "[]"
                "base_resources_provided_json": resources_provided_json,
                "res_mode": str(policy.get("res_mode") or "reset"),
                "res_grant_interval": str(policy.get("res_grant_interval") or "month"),
                "res_grant_interval_count": str(int(policy.get("res_grant_interval_count") or 1)),
                "active_price_id": active_price_id,
                "active_product_id": active_product_id or "",
            }

        # 8) Impostazioni customer_update / tax / billing address SOLO da policy
        cu = dict(policy.get("customer_update") or {})
        automatic_tax = policy.get("automatic_tax") or {"enabled": True}
        tax_id_collection = policy.get("tax_id_collection") or {"enabled": True}
        billing_address_collection = policy.get("billing_address_collection") or "required"

        # 9) Dati subscription (trial solo da policy)
        sub_data: Dict[str, Any] = {"metadata": subscription_metadata}
        if policy.get("trial_period_days") is not None:
            sub_data["trial_period_days"] = int(policy["trial_period_days"])

        # 10) Crea la Checkout Session con i soli parametri previsti da policy
        create_kwargs: Dict[str, Any] = dict(
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
            line_items=[{"price": price_id, "quantity": 1}],  # quantity fissata lato server
            customer=customer_id,
            client_reference_id=user["user_ref"],
            allow_promotion_codes=bool(policy.get("allow_promotion_codes", False)),
            automatic_tax=automatic_tax,
            tax_id_collection=tax_id_collection,
            locale=payload.locale,  # solo UX
            billing_address_collection=billing_address_collection,
            subscription_data=sub_data,
            idempotency_key=_idem(base_idem, "checkout.session.create.dynamic-or-variant-v2"),
            **opts,
        )

        # Pass-through opzionali da policy (se presenti)
        if cu:
            create_kwargs["customer_update"] = cu
        if policy.get("payment_settings"):
            create_kwargs["payment_settings"] = policy["payment_settings"]
        if policy.get("payment_behavior"):
            create_kwargs["payment_behavior"] = policy["payment_behavior"]

        # 11) Crea la sessione di Checkout
        session = stripe.checkout.Session.create(**create_kwargs)

        # 12) Response
        return {
            "id": session["id"],
            "url": session["url"],
            "customer_id": session.get("customer"),
            "created_product_id": created_product_id,
            "created_price_id": price_id,
        }

    except HTTPException:
        raise
    except Exception as e:
        _raise_from_stripe_error(e)



@router.post(
    "/portal/session",
    summary="Crea un link al Billing Portal per l'UTENTE CORRENTE (selettore 'portal' con override)",
    dependencies=[Security(require_admin_api_key)],
)
def me_billing_portal(
    request: Request,
    payload: PortalSessionRequest = Body(...),  # ⬅️ nuovo schema: contiene 'portal'

):
    """
    Genera una Billing Portal Session per l'utente corrente usando un *selettore di configurazione*:
      - `payload.portal` è un PortalConfigSelector completo (configuration_id già esistente OPPURE
        plan_type + variants_override/portal_preset + eventuali override di features/business_profile).
      - Non c'è più logica di 'preset' a livello endpoint: l'eventuale preset è risolto all'interno
        del selettore (o ignorato se usi variants_override).
    """

    # 1) Auth: JWT utente + API Key admin
    user = request.state.user
    access_token = request.state.access_token

    # 2) Stripe opts (es. Connect) + Idempotency
    opts = _opts_from_request(request)
    base_idem = _base_idem_from_request(request)

    # 3) Trova/crea il Customer dell'utente
    try:
        customer_id = _get_or_ensure_customer_id_cached(
            user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
        )
    except Exception as e:
        _raise_from_stripe_error(e)


    # 4) Validazione return_url contro allowlist
    ret_url = _validate_return_url(payload.return_url)

    # 5) Risolvi/riusa la Billing Portal Configuration dal selettore passato

    try:
        config_id = _resolve_portal_configuration_id(
            selector=payload.portal,
            base_idem=base_idem,
            opts=opts,
        )
    except HTTPException:
        # errori domain-specific già formattati
        raise
    except Exception as e:
        # errori Stripe generici → adattati
        _raise_from_stripe_error(e)

    # 6) Crea la session del Billing Portal

    try:
        create_kwargs = {
            "customer": customer_id,
            "return_url": ret_url,
            "configuration": config_id,
            "idempotency_key": _idem(base_idem, f"portal.session.{customer_id}.{config_id}"),
            **opts,
        }
        # flow_data è opzionale: invialo solo se presente per evitare 'null'
        if payload.flow_data:
            create_kwargs["flow_data"] = payload.flow_data

        sess = stripe.billing_portal.Session.create(**create_kwargs)


        return {"id": sess["id"], "url": sess["url"], "configuration_id": config_id}
    except HTTPException:
        raise
    except Exception as e:
        _raise_from_stripe_error(e)


# >>> ADD: endpoint - UPDATE (upgrade/downgrade)
@router.post("/portal/deeplinks/update", summary="Crea un deep-link al Portal per aggiornare il piano (JWT + API Key)",
             dependencies=[Security(require_admin_api_key)],)
def me_portal_deeplink_update(
    request: Request,
    payload: PortalUpdateDeepLinkRequest = Body(...),
):
    user = request.state.user
    access_token = request.state.access_token

    opts = _opts_from_request(request)
    ret_url = _validate_return_url(payload.return_url)

    # ownership
    sub = stripe.Subscription.retrieve(payload.subscription_id, **opts)
    customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
    _ensure_subscription_ownership(sub, customer_id)

    base_idem = _base_idem_from_request(request)
    config_id = _resolve_portal_configuration_id(selector=payload.portal, base_idem=base_idem, opts=opts)

    sess = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=ret_url,
        configuration=config_id,
        flow_data={
            "type": "subscription_update",
            "subscription_update": {"subscription": payload.subscription_id},
            "after_completion": {
                "type": "redirect",
                "redirect": {
                    "return_url": ret_url  # ← usa la vostra URL applicativa
                }
            },
        },
        **opts,
    )
    return {"url": sess["url"], "id": sess["id"], "configuration_id": config_id}


@router.post(
    "/portal/deeplinks/upgrade",
    summary="Crea un deep-link *confermato* al Portal per upgrade/downgrade del piano (JWT + API Key)",
    dependencies=[Security(require_admin_api_key)],
)
def me_portal_deeplink_upgrade(
    request: Request,
    payload: PortalUpgradeDeepLinkRequest = Body(...),
):
    """
    Deeplink confermato al Billing Portal per upgrade/downgrade con sconti opzionali:
      - coupon_id / promotion_code
      - discounts (array raw pass-through)
      - raw_discounts (NUOVO): specifiche "grezze" percentuali o a importo → crea Coupon e lo applica
    """
    # 1) Autorizzazioni e contesto
    user = request.state.user
    access_token = request.state.access_token

    opts = _opts_from_request(request)
    ret_url = _validate_return_url(payload.return_url)
    base_idem = _base_idem_from_request(request)

    # 2) Ownership subscription (espansione items per ricavare l'item id)
    sub = stripe.Subscription.retrieve(
        payload.subscription_id,
        expand=["items.data.price.product"],
        **opts,
    )
    customer_id = _get_or_ensure_customer_id_cached(
        user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
    )
    _ensure_subscription_ownership(sub, customer_id)

    # 3) Risolvi/riusa configuration dal selettore 'portal'
    config_id = _resolve_portal_configuration_id(
        selector=payload.portal,
        base_idem=base_idem,
        opts=opts,
    )

    # 4) Determina target price (esplicito o da plan_type+variant)
    target_price_id = payload.target_price_id
    target_product_id = None
    target_currency = "eur"
    if not target_price_id:
        if not payload.target_plan_type or not payload.target_variant:
            raise HTTPException(
                status_code=400,
                detail="Serve 'target_price_id' oppure 'target_plan_type' + 'target_variant'."
            )
        # ⬇️ Ora _ensure_price_for_variant ritorna (price_id, product_id, price_obj)
        target_price_id, target_product_id, price_obj = _ensure_price_for_variant(
            plan_type=payload.target_plan_type,
            variant=payload.target_variant,
            base_idem=base_idem,
            opts=opts,
            allow_fallback_equivalent_any=True,
            reactivate_if_inactive=True,
        )
        # Evita retrieve extra: ricava currency/product dal price_obj
        rec_prod = price_obj.get("product")
        target_product_id = (rec_prod.get("id") if isinstance(rec_prod, dict) else rec_prod) or target_product_id
        target_currency = price_obj.get("currency") or target_currency
    else:
        # Se il caller ha fornito direttamente il price_id, recupera SOLO ciò che serve una volta
        # (puoi anche accettare un leggero round-trip qui, ma resta un’unica chiamata)
        pr = stripe.Price.retrieve(target_price_id, **opts)
        rec_prod = pr.get("product")
        target_product_id = rec_prod.get("id") if isinstance(rec_prod, dict) else rec_prod
        target_currency = pr.get("currency") or target_currency

    # 5) Normalizza quantità
    qty = int(payload.quantity or 1)
    if qty < 1:
        qty = 1

    # 6) Individua l'item da aggiornare e includi l'ID nel flow_data
    items = (sub.get("items", {}) or {}).get("data") or []
    if not items:
        raise HTTPException(status_code=400, detail="Subscription priva di items aggiornabili.")

    def _item_product_id(it: Dict[str, Any]) -> Optional[str]:
        pr = it.get("price") or {}
        prod = pr.get("product")
        return prod.get("id") if isinstance(prod, dict) else prod

    candidate = None
    if target_product_id:
        candidate = next((it for it in items if not it.get("deleted") and _item_product_id(it) == target_product_id), None)
    if not candidate:
        candidate = next((it for it in items if not it.get("deleted")), None)
    if not candidate:
        raise HTTPException(status_code=400, detail="Nessun subscription item aggiornabile trovato.")
    sub_item_id = candidate["id"]

    # 7) Costruisci l'array sconti (unione di tutte le fonti)
    discounts: List[Dict[str, Any]] = list(payload.discounts or [])
    if payload.coupon_id:
        discounts.append({"coupon": payload.coupon_id})
    if payload.promotion_code:
        discounts.append({"promotion_code": payload.promotion_code})

    # 7.a) NUOVO: crea coupon "al volo" per ogni raw_discount e aggiungilo a discounts
    for i, spec in enumerate(payload.raw_discounts or []):
        try:
            idem_suffix = (
                f"coupon.raw.{spec.kind}."
                f"{spec.percent_off or spec.amount_off}."
                f"{(spec.currency or target_currency) if spec.kind=='amount' else 'na'}."
                f"{spec.duration}.{spec.duration_in_months or 0}."
                f"{spec.name or ''}"
            )
            create_kwargs: Dict[str, Any] = {
                "duration": spec.duration,
                "idempotency_key": _idem(base_idem, idem_suffix),
                **({"name": spec.name} if spec.name else {}),
            }
            if spec.duration == "repeating":
                if not spec.duration_in_months:
                    raise HTTPException(status_code=400, detail="raw_discount.duration_in_months richiesto quando duration='repeating'")
                create_kwargs["duration_in_months"] = int(spec.duration_in_months)

            if spec.kind == "percent":
                create_kwargs["percent_off"] = float(spec.percent_off)
            else:
                currency = (spec.currency or target_currency)
                create_kwargs["amount_off"] = int(spec.amount_off)
                create_kwargs["currency"] = currency

            coupon = stripe.Coupon.create(**create_kwargs, **opts)
            discounts.append({"coupon": coupon["id"]})
        except HTTPException:
            raise
        except Exception as e:
            _raise_from_stripe_error(e)

    # 8) Flow confermato per il Portal (includendo l'ID dell'item + sconti)
    flow_data = {
        "type": "subscription_update_confirm",
        "subscription_update_confirm": {
            "subscription": payload.subscription_id,
            "items": [
                {
                    "id": sub_item_id,
                    "price": target_price_id,
                    "quantity": qty,
                }
            ],
            **({"discounts": discounts} if discounts else {}),
        },
        "after_completion": {
            "type": "redirect",
            "redirect": {"return_url": ret_url},
        },
    }

    # 9) Crea la session del Billing Portal
    try:
        sess = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=ret_url,
            configuration=config_id,
            flow_data=flow_data,
            idempotency_key=_idem(
                base_idem,
                f"portal.upgrade.{customer_id}.{payload.subscription_id}.{target_price_id}.{qty}"
            ),
            **opts,
        )
        return {
            "url": sess["url"],
            "id": sess["id"],
            "configuration_id": config_id,
            "target_price_id": target_price_id,
            # manteniamo la chiave storica ma ora contiene l'ID product target (può essere esistente)
            "created_product_id": target_product_id,
        }
    except HTTPException:
        raise
    except Exception as e:
        _raise_from_stripe_error(e)


# >>> ADD: endpoint - CANCEL
@router.post("/portal/deeplinks/cancel", summary="Crea un deep-link al Portal per cancellare il piano (JWT + API Key)",
             dependencies=[Security(require_admin_api_key)],)
def me_portal_deeplink_cancel(
    request: Request,
    payload: PortalCancelDeepLinkRequest = Body(...),
):
    user = request.state.user
    access_token = request.state.access_token

    opts = _opts_from_request(request)
    ret_url = _validate_return_url(payload.return_url)

    sub = stripe.Subscription.retrieve(payload.subscription_id, **opts)
    customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
    _ensure_subscription_ownership(sub, customer_id)

    base_idem = _base_idem_from_request(request)
    # se immediate=True, forziamo una config con cancel immediato
    features_override = None
    if payload.immediate:
        features_override = PortalFeaturesOverride(
            subscription_cancel={"enabled": True, "mode": "immediately"}
        )
        if not payload.portal.features_override:
            payload.portal.features_override = features_override
        else:
            # merge minimal: diamo priorità al flag immediato
            cur = payload.portal.features_override.model_dump() or {}
            cur["subscription_cancel"] = {"enabled": True, "mode": "immediately"}
            payload.portal.features_override = PortalFeaturesOverride(**cur)

    config_id = _resolve_portal_configuration_id(selector=payload.portal, base_idem=base_idem, opts=opts)

    sess = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=ret_url,
        configuration=config_id,
        flow_data={"type": "subscription_cancel",
                   "subscription_cancel": {"subscription": payload.subscription_id},
                   "after_completion": {
                       "type": "redirect",
                       "redirect": {
                           "return_url": ret_url  # ← usa la vostra URL applicativa
                       }
                   },
                   },
        **opts,
    )
    return {"url": sess["url"], "id": sess["id"], "configuration_id": config_id}

@router.get(
    "/subscriptions/{subscription_id}/resources",
    summary="Risorse del piano per la Subscription (provided, used, remaining) — UTENTE",
)
def me_get_subscription_resources(
    subscription_id: str,
    request: Request,
):
    # 1) Auth utente (JWT) e contesto
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    # 2) Trova/garantisce il Customer dell'utente corrente
    customer_id = _get_or_ensure_customer_id_cached(
        user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
    )

    # 3) Carica la subscription e verifica doppia ownership
    #    (a) subscription.customer === customer_id
    #    (b) metadata.internal_customer_ref === user["user_ref"] (se presente)
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    if str(sub.get("customer")) != str(customer_id):
        raise HTTPException(status_code=403, detail="Subscription non appartiene all'utente.")
    md = sub.get("metadata") or {}
    internal_ref = md.get("internal_customer_ref")
    if internal_ref and str(internal_ref) != str(user["user_ref"]):
        raise HTTPException(status_code=403, detail="Mismatch internal_customer_ref vs user_ref.")

    # 4) SYNC LAZY varianti (upgrade/downgrade) + ROLLOVER allineato a Stripe.
    #    Questo aggiorna i metadata della subscription se l'item/price attivo è cambiato
    #    (es. utente ha cambiato piano/periodicità dal Billing Portal).
    _sync_subscription_variant_state(subscription_id, opts)
    _maybe_rollover_resources_stripe_aligned(subscription_id, opts)

    # 5) Ricarica subscription/metadata dopo l’eventuale sync/rollover
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    md = sub.get("metadata") or {}

    # 6) Period bounds robusti (anche se current_period_* risultano null)
    period_start, period_end = _infer_period_bounds(sub)

    # 7) Estrai/normalizza risorse dai metadata aggiornati
    provided = _parse_resources_json(md.get("resources_provided_json"))
    used = _parse_resources_json(md.get("resources_used_json"))
    requested = _parse_resources_json(md.get("resources_requested_json"))
    remaining = _compute_remaining(provided, used)

    # 8) Risposta arricchita (variant, active_price_id) e periodi robusti
    return {
        "subscription_id": subscription_id,
        "plan_type": md.get("plan_type"),
        "variant": md.get("variant"),
        "pricing_method": md.get("pricing_method"),
        "active_price_id": md.get("active_price_id"),
        "resources": {
            "requested": requested,
            "provided": provided,
            "used": used,
            "remaining": remaining,
        },
        "period_start": period_start,  # calcolato robustamente
        "period_end": period_end,      # calcolato robustamente
        "customer_id": customer_id,
    }

'''
@router.post(
    "/subscriptions/{subscription_id}/resources/consume",
    summary="Consuma risorse della Subscription — SERVER (JWT + API Key)",
dependencies=[Security(require_admin_api_key)],
)
def consume_subscription_resources(
    subscription_id: str,
    payload: ConsumeResourcesRequest = Body(...),
    request: Request = None,

):

    # 1) Autorizzazioni: JWT utente + API Key server
    user = request.state.user
    access_token = request.state.access_token

    opts = _opts_from_request(request)

    # 2) Customer dell'utente
    customer_id = _get_or_ensure_customer_id_cached(
        user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
    )

    # 3) Carica subscription e verifica doppia ownership
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    if str(sub.get("customer")) != str(customer_id):
        raise HTTPException(status_code=403, detail="Subscription non appartiene all'utente.")
    md = sub.get("metadata") or {}
    internal_ref = md.get("internal_customer_ref")
    if internal_ref and str(internal_ref) != str(user["user_ref"]):
        raise HTTPException(status_code=403, detail="Mismatch internal_customer_ref vs user_ref.")

    # 4) SYNC LAZY (upgrade/downgrade) + ROLLOVER allineato a Stripe;
    #    poi ricarichiamo la subscription con eventuali aggiornamenti.
    _sync_subscription_variant_state(subscription_id, opts)
    _maybe_rollover_resources_stripe_aligned(subscription_id, opts)
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    md = sub.get("metadata") or {}

    # 5) Concurrency guard opzionale (se il client passa attesi)
    if payload.expected_plan_type and payload.expected_plan_type != md.get("plan_type"):
        raise HTTPException(
            status_code=409,
            detail=f"Plan type cambiato: atteso '{payload.expected_plan_type}', attuale '{md.get('plan_type')}'"
        )
    if payload.expected_variant and payload.expected_variant != md.get("variant"):
        raise HTTPException(
            status_code=409,
            detail=f"Variant cambiata: attesa '{payload.expected_variant}', attuale '{md.get('variant')}'"
        )

    # 6) Period bounds robusti (anche se current_period_* sono null)
    period_start, period_end = _infer_period_bounds(sub)

    # 7) Risorse attuali e validazione vincoli delta (step)
    provided = _parse_resources_json(md.get("resources_provided_json"))
    used = _parse_resources_json(md.get("resources_used_json"))
    plan_type = md.get("plan_type") or ""
    delta_list = [it.model_dump() for it in payload.items]

    _assert_consume_constraints(plan_type, delta_list)

    # 8) Calcola il nuovo "used" sommando il delta richiesto
    new_used_map = _to_map(used)
    for it in delta_list:
        k = (it.get("key"), it.get("unit"))
        q = float(it.get("quantity", 0) or 0)
        # q < 0 è già intercettato da _assert_consume_constraints, ma manteniamo il guardrail
        if q < 0:
            raise HTTPException(status_code=400, detail="Quantità negativa non consentita nel consumo.")
        new_used_map[k] = new_used_map.get(k, 0.0) + q
    new_used = _to_list(new_used_map)

    # 9) Guardrail: non superare il provided

    _assert_not_exceed(provided, new_used)

    # 10) Aggiorna i metadata in Stripe
    patch_md = {**md, "resources_used_json": json.dumps(new_used, separators=(",", ":"))}
    if payload.reason:
        patch_md["resources_last_reason"] = payload.reason

    updated = stripe.Subscription.modify(subscription_id, metadata=patch_md, **opts)

    # 11) Remaining e risposta
    remaining = _compute_remaining(provided, new_used)
    return {
        "subscription_id": subscription_id,
        "resources": {
            "provided": provided,
            "used": new_used,
            "remaining": remaining,
        },
        "metadata": {
            "plan_type": updated["metadata"].get("plan_type"),
            "variant": updated["metadata"].get("variant"),
            "pricing_method": updated["metadata"].get("pricing_method"),
        },
        "active_price_id": updated["metadata"].get("active_price_id"),
        "period_start": period_start,
        "period_end": period_end,
        "customer_id": customer_id,
    }'''

@router.post(
    "/subscriptions/{subscription_id}/resources/consume",
    summary="Consuma risorse della Subscription — SERVER (JWT + API Key)",
    dependencies=[Security(require_admin_api_key)],
)
def consume_subscription_resources(
    subscription_id: str,
    payload: ConsumeResourcesRequest = Body(...),
    request: Request = None,
):
    # 1) Contesto + Stripe opts
    user = request.state.user
    opts = _opts_from_request(request)

    # 2) Carica UNA volta la Subscription (niente expand: basta il suboggetto price “light”)
    sub = stripe.Subscription.retrieve(subscription_id, **opts)
    md = sub.get("metadata") or {}

    # 3) Ownership (fail-fast): se internal_customer_ref non combacia, 403 immediato
    internal_ref = md.get("internal_customer_ref")
    if internal_ref and str(internal_ref) != str(user["user_ref"]):
        raise HTTPException(status_code=403, detail="Mismatch internal_customer_ref vs user_ref.")

    # 3.b) Doppia ownership (customer): esegui SOLO qui la risoluzione del customer_id
    customer_id = _get_or_ensure_customer_id_cached(
        user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
    )
    if str(sub.get("customer")) != str(customer_id):
        raise HTTPException(status_code=403, detail="Subscription non appartiene all'utente.")

    # 4) SYNC + ROLLOVER fast (zero re-retrieve; al massimo 1 Price.retrieve se serve)
    patch_md_sync_roll, provided, used, changed = _fast_sync_and_rollover_in_memory(sub, opts)

    # 5) Concurrency guards (post-sync): confronta con i valori EFFETTIVI
    effective_md = {**md, **patch_md_sync_roll}
    if payload.expected_plan_type and payload.expected_plan_type != effective_md.get("plan_type"):
        raise HTTPException(
            status_code=409,
            detail=f"Plan type cambiato: atteso '{payload.expected_plan_type}', attuale '{effective_md.get('plan_type')}'"
        )
    if payload.expected_variant and payload.expected_variant != effective_md.get("variant"):
        raise HTTPException(
            status_code=409,
            detail=f"Variant cambiata: attesa '{payload.expected_variant}', attuale '{effective_md.get('variant')}'"
        )

    # 6) Period bounds robusti (possiamo usare la sub già in mano)
    period_start, period_end = _infer_period_bounds(sub)

    # 7) Validazione vincoli delta e calcolo nuovo "used"
    plan_type = effective_md.get("plan_type") or ""
    delta_list = [it.model_dump() for it in payload.items]
    _assert_consume_constraints(plan_type, delta_list)

    new_used_map = _to_map(used)
    for it in delta_list:
        k = (it.get("key"), it.get("unit"))
        q = float(it.get("quantity", 0) or 0)
        if q < 0:
            raise HTTPException(status_code=400, detail="Quantità negativa non consentita nel consumo.")
        new_used_map[k] = new_used_map.get(k, 0.0) + q
    new_used = _to_list(new_used_map)

    # 8) Guardrail: non superare il provided “post sync/rollover”
    _assert_not_exceed(provided, new_used)

    # 9) Unico PATCH a Stripe (merge: sync/rollover + consumo)
    final_patch = dict(effective_md)  # base = md + patch_sync_roll
    final_patch["resources_used_json"] = json.dumps(new_used, separators=(",", ":"))
    if payload.reason:
        final_patch["resources_last_reason"] = payload.reason

    updated = stripe.Subscription.modify(subscription_id, metadata=final_patch, **opts)

    # 10) Remaining & risposta
    remaining = _compute_remaining(provided, new_used)
    return {
        "subscription_id": subscription_id,
        "resources": {
            "provided": provided,
            "used": new_used,
            "remaining": remaining,
        },
        "metadata": {
            "plan_type": updated["metadata"].get("plan_type"),
            "variant": updated["metadata"].get("variant"),
            "pricing_method": updated["metadata"].get("pricing_method"),
        },
        "active_price_id": updated["metadata"].get("active_price_id"),
        "period_start": period_start,
        "period_end": period_end,
        "customer_id": customer_id,
    }

@router.post(
    "/subscriptions/{subscription_id}/resources/set",
    summary="Setta/Sovrascrive le risorse fornite della Subscription — SERVER (JWT + API Key)",
dependencies=[Security(require_admin_api_key)],
)
def set_subscription_resources(
    subscription_id: str,
    payload: SetResourcesRequest = Body(...),
    request: Request = None,
):
    # 1) Autorizzazioni: JWT utente + API Key server
    user = request.state.user
    access_token = request.state.access_token

    opts = _opts_from_request(request)

    # 2) Customer dell'utente
    customer_id = _get_or_ensure_customer_id_cached(
        user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
    )

    # 3) Carica subscription e verifica doppia ownership
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    if str(sub.get("customer")) != str(customer_id):
        raise HTTPException(status_code=403, detail="Subscription non appartiene all'utente.")
    md = sub.get("metadata") or {}
    internal_ref = md.get("internal_customer_ref")
    if internal_ref and str(internal_ref) != str(user["user_ref"]):
        raise HTTPException(status_code=403, detail="Mismatch internal_customer_ref vs user_ref.")

    # 4) SYNC LAZY (upgrade/downgrade) + ROLLOVER; poi ricarica
    _sync_subscription_variant_state(subscription_id, opts)
    _maybe_rollover_resources_stripe_aligned(subscription_id, opts)
    sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price.product"], **opts)
    md = sub.get("metadata") or {}

    # 5) Concurrency guard opzionale
    if payload.expected_plan_type and payload.expected_plan_type != md.get("plan_type"):
        raise HTTPException(
            status_code=409,
            detail=f"Plan type cambiato: atteso '{payload.expected_plan_type}', attuale '{md.get('plan_type')}'"
        )
    if payload.expected_variant and payload.expected_variant != md.get("variant"):
        raise HTTPException(
            status_code=409,
            detail=f"Variant cambiata: attesa '{payload.expected_variant}', attuale '{md.get('variant')}'"
        )

    # 6) Period bounds robusti
    period_start, period_end = _infer_period_bounds(sub)

    # 7) Prepara nuovo "provided" e "used"
    plan_type = md.get("plan_type") or ""
    new_provided = [it.model_dump() for it in payload.resources_provided]

    # 8) Validazione vincoli min/max/step sui nuovi provided
    _assert_set_constraints(plan_type, new_provided)

    if payload.reset_used:
        new_used = []
    else:
        current_used = _parse_resources_json(md.get("resources_used_json"))
        # non permettere che l'usato corrente ecceda il nuovo plafond
        _assert_not_exceed(new_provided, current_used)
        new_used = current_used

    # 9) Aggiorna metadata su Stripe
    patch_md = {
        **md,
        "resources_provided_json": json.dumps(new_provided, separators=(",", ":")),
        "resources_used_json": json.dumps(new_used, separators=(",", ":")),
    }
    if payload.reason:
        patch_md["resources_last_reason"] = payload.reason

    updated = stripe.Subscription.modify(subscription_id, metadata=patch_md, **opts)

    # 10) Remaining e risposta
    remaining = _compute_remaining(new_provided, new_used)
    return {
        "subscription_id": subscription_id,
        "resources": {
            "provided": new_provided,
            "used": new_used,
            "remaining": remaining,
        },
        "metadata": {
            "plan_type": updated["metadata"].get("plan_type"),
            "variant": updated["metadata"].get("variant"),
            "pricing_method": updated["metadata"].get("pricing_method"),
        },
        "active_price_id": updated["metadata"].get("active_price_id"),
        "period_start": period_start,
        "period_end": period_end,
        "customer_id": customer_id,
    }



# ---------------------- CONSULTAZIONE (ME) ----------------------

@router.get(
    "/subscriptions",
    summary="Lista abbonamenti dell'UTENTE CORRENTE",
)
def me_list_subscriptions(
    request: Request,
    status_filter: Optional[str] = None,
    limit: int = 10,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        t_1 = time.time()
        customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        t_2 = time.time()
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status_filter:
            params["status"] = status_filter
        subscriptions = stripe.Subscription.list(**params, **opts)
        t_3 = time.time()
        print("#"*120)
        print(t_2 - t_1, t_3 - t_2)
        print("#" * 120)
        return subscriptions
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/subscriptions/{subscription_id}",
    summary="Dettaglio Subscription dell'UTENTE CORRENTE",
)
def me_get_subscription(
    subscription_id: str,
    request: Request,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.retrieve(subscription_id, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/payment-methods",
    summary="PaymentMethods dell'UTENTE CORRENTE",
)
def me_list_payment_methods(
    request: Request,
    type: str = "card",
    limit: int = 10,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        return stripe.PaymentMethod.list(customer=customer_id, type=type, limit=limit, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/invoices",
    summary="Storico fatture (Invoices) dell'UTENTE CORRENTE",
)
def me_list_invoices(
    request: Request,
    limit: int = 10,
    status: Optional[str] = None,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        params: Dict[str, Any] = {"customer": customer_id, "limit": limit}
        if status:
            params["status"] = status
        return stripe.Invoice.list(**params, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.get(
    "/charges",
    summary="Storico addebiti (Charges) dell'UTENTE CORRENTE",
)
def me_list_charges(
    request: Request,
    limit: int = 10,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        customer_id = _get_or_ensure_customer_id_cached(user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts)
        return stripe.Charge.list(customer=customer_id, limit=limit, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


# ---------------------- AZIONI (ME) ----------------------

@router.post(
    "/subscriptions/{subscription_id}/cancel",
    summary="Cancella una Subscription dell'UTENTE CORRENTE",
)
def me_cancel_subscription(
    subscription_id: str,
    payload: CancelRequest = Body(...),
    request: Request = None,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        if payload.cancel_now:
            return stripe.Subscription.delete(
                subscription_id,
                invoice_now=payload.invoice_now,
                prorate=payload.prorate,
                **opts
            )
        else:
            return stripe.Subscription.modify(subscription_id, cancel_at_period_end=True, **opts)
    except Exception as e:
        _raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/pause",
    summary="Pausa la riscossione di una Subscription (ME)",
)
def me_pause_subscription(
    subscription_id: str,
    payload: PauseRequest = Body(...),
    request: Request = None,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.modify(
            subscription_id,
            pause_collection={
                "behavior": payload.behavior,
                **({"resumes_at": payload.resumes_at} if payload.resumes_at else {}),
            },
            **opts
        )
    except Exception as e:
        _raise_from_stripe_error(e)


@router.post(
    "/subscriptions/{subscription_id}/resume",
    summary="Riprende una Subscription in pausa (ME)",
)
def me_resume_subscription(
    subscription_id: str,
    payload: ResumeRequest = Body(default=ResumeRequest()),
    request: Request = None,

):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        return stripe.Subscription.resume(
            subscription_id,
            billing_cycle_anchor=payload.billing_cycle_anchor,
            proration_behavior=payload.proration_behavior,
            **opts
        )
    except Exception as e:
        _raise_from_stripe_error(e)



@router.post(
    "/payment-methods/attach",
    summary="Collega un PaymentMethod all'UTENTE CORRENTE (+ opz. set default su Subscription)",
    description="""
Collega un PaymentMethod (pm_...) al Customer dell'utente autenticato.  
- Il PM deve essere creato sul frontend (Stripe.js/SetupIntent).  
- Se `set_as_default_for_subscription_id` è passato, il PM diventa default per quella Subscription.  
""",
)
def me_attach_payment_method(
    payload: AttachMeRequest = Body(...),
    request: Request = None,
):
    user = request.state.user
    access_token = request.state.access_token
    opts = _opts_from_request(request)

    try:
        # Trova/crea Customer per l’utente
        customer_id = _get_or_ensure_customer_id_cached(
            user_ref=user["user_ref"], email=user["email"], name=user["name"], opts=opts
        )

        # 1) attach PaymentMethod
        pm = stripe.PaymentMethod.attach(payload.payment_method_id, customer=customer_id, **opts)

        # 2) opzionale: set default per Subscription
        if payload.set_as_default_for_subscription_id:
            stripe.Subscription.modify(
                payload.set_as_default_for_subscription_id,
                default_payment_method=payload.payment_method_id,
                **opts,
            )

        return pm
    except Exception as e:
        _raise_from_stripe_error(e)
