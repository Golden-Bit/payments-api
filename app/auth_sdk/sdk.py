import requests
from pydantic import BaseModel, Field
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# MODELLI DI DATI
# ---------------------------------------------------------------------------

class SignUpRequest(BaseModel):
    username: str = Field(..., description="Nome utente per la registrazione")
    password: str = Field(..., description="Password per l'utente")
    email: str = Field(..., description="Indirizzo email dell'utente")


class SignInRequest(BaseModel):
    username: str = Field(..., description="Nome utente per l'autenticazione")
    password: str = Field(..., description="Password dell'utente")


class ConfirmSignUpRequest(BaseModel):
    username: str = Field(..., description="Nome utente da confermare")
    confirmation_code: str = Field(..., description="Codice di conferma ricevuto via email")


class ResendConfirmationCodeRequest(BaseModel):
    username: str = Field(..., description="Nome utente per cui inviare il nuovo codice di conferma")


class UserAttribute(BaseModel):
    Name: str = Field(..., description="Nome dell'attributo")
    Value: str = Field(..., description="Valore dell'attributo")


class UpdateAttributesRequest(BaseModel):
    access_token: str = Field(..., description="Token di accesso dell'utente")
    attributes: List[UserAttribute] = Field(..., description="Lista degli attributi da aggiornare")


class UpdateCustomAttributesRequest(BaseModel):
    access_token: str = Field(..., description="Token di accesso dell'utente")
    custom_attributes: Dict[str, str] = Field(
        ...,
        description=(
            "Dizionario degli attributi customizzati, ad esempio: "
            "{ 'custom:department': 'Marketing', 'custom:role': 'Manager' }"
        )
    )


class AccessTokenRequest(BaseModel):
    access_token: str = Field(..., description="Access token rilasciato da Cognito per l'utente")


class ConfirmForgotPasswordRequest(BaseModel):
    username: str = Field(..., description="Nome utente per cui completare il reset della password")
    confirmation_code: str = Field(
        ...,
        description="Codice di conferma ricevuto via email/SMS da Cognito"
    )
    new_password: str = Field(..., description="Nuova password da impostare per l'utente")


class RefreshTokenRequest(BaseModel):
    username: str = Field(..., description="Nome utente per cui effettuare il rinnovo dei token")
    refresh_token: str = Field(
        ...,
        description="Refresh Token ottenuto durante il processo di autenticazione"
    )


class ForgotPasswordRequest(BaseModel):
    username: str = Field(..., description="Nome utente per il quale avviare il recupero password")


class ChangePasswordRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente autenticato")
    old_password: str = Field(..., description="Vecchia password attualmente in uso")
    new_password: str = Field(..., description="Nuova password da impostare")


class VerifyAttributeRequest(BaseModel):
    access_token: str = Field(..., description="Access token rilasciato da Cognito per l'utente")
    attribute_name: str = Field(
        ...,
        description="Nome dell'attributo da verificare, es. 'email' o 'phone_number'"
    )


class ConfirmAttributeRequest(BaseModel):
    access_token: str = Field(..., description="Access token dell'utente")
    attribute_name: str = Field(
        ...,
        description="Nome dell'attributo da confermare, es. 'email' o 'phone_number'"
    )
    confirmation_code: str = Field(
        ...,
        description="Codice di verifica ricevuto via SMS o email"
    )

class MfaRespondChallengeRequest(BaseModel):
    session: str = Field(..., description="Session restituita da Cognito dopo initiate_auth")
    challenge_name: str = Field(..., description="Nome del challenge, es. 'SMS_MFA' o 'SOFTWARE_TOKEN_MFA'")
    username: str = Field(..., description="Nome utente")
    code: str = Field(..., description="Codice OTP inviato via SMS o generato dall'app TOTP")

class EnableSmsMfaRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente autenticato")
    phone_number: str = Field(..., description="Numero di telefono verificato in formato E.164 (es. +391234567890)")

class DisableMfaRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente")

class AssociateSoftwareTokenRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente autenticato")

class VerifySoftwareTokenRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente")
    friendly_device_name: str = Field("", description="Nome del dispositivo (opzionale)")
    code: str = Field(..., description="Codice TOTP generato dall'app (6 cifre)")

class AccessTokenOnlyRequest(BaseModel):
    access_token: str = Field(..., description="Access Token dell'utente autenticato")

class SocialLoginRequest(BaseModel):
    provider: str = Field(..., description="Nome del provider (Google, Facebook, Apple, Amazon, etc.)")

class SocialCallbackRequest(BaseModel):
    code: str = Field(..., description="Codice di autorizzazione da scambiare per i token")
    state: Optional[str] = Field(None, description="Parametro di stato (opzionale) per protezione CSRF")


# ---------------------------------------------------------------------------
# CLASSE SDK
# ---------------------------------------------------------------------------

class CognitoSDK:
    """
    SDK per interagire con le API di autenticazione e gestione utenti basate su Amazon Cognito.
    Mappa tutti gli endpoint esposti dal servizio.
    """

    def __init__(self, base_url: str):
        """
        Inizializza l'SDK con l'URL base dell'API.

        Args:
            base_url (str): L'URL base dell'API (es. "http://localhost:8000")
        """
        self.base_url = base_url.rstrip('/')
        self.headers = {"Content-Type": "application/json"}

    def signup(self, data: SignUpRequest) -> dict:
        """
        Registra un nuovo utente.
        Endpoint: POST /v1/user/signup
        """
        url = f"{self.base_url}/v1/user/signup"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def signin(self, data: SignInRequest) -> dict:
        """
        Autentica un utente.
        Endpoint: POST /v1/user/signin
        """
        url = f"{self.base_url}/v1/user/signin"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def verify_token(self, data: AccessTokenRequest) -> dict:
        """
        Verifica e decodifica un token JWT.
        Endpoint: POST /v1/user/verify-token
        """
        url = f"{self.base_url}/v1/user/verify-token"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def confirm_signup_user(self, data: ConfirmSignUpRequest) -> dict:
        """
        Conferma la registrazione di un utente tramite codice di conferma.
        Endpoint: POST /v1/user/confirm-signup-user
        """
        url = f"{self.base_url}/v1/user/confirm-signup-user"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def resend_confirmation_code(self, data: ResendConfirmationCodeRequest) -> dict:
        """
        Reinvia il codice di conferma per la registrazione.
        Endpoint: POST /v1/user/resend-confirmation-code
        """
        url = f"{self.base_url}/v1/user/resend-confirmation-code"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def update_attributes(self, data: UpdateAttributesRequest) -> dict:
        """
        Aggiorna gli attributi standard di un utente.
        Endpoint: POST /v1/user/update-attributes
        """
        url = f"{self.base_url}/v1/user/update-attributes"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def update_custom_attributes(self, data: UpdateCustomAttributesRequest) -> dict:
        """
        Aggiorna gli attributi custom di un utente.
        Endpoint: POST /v1/user/update-custom-attributes
        """
        url = f"{self.base_url}/v1/user/update-custom-attributes"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def get_user_info(self, data: AccessTokenRequest) -> dict:
        """
        Recupera le informazioni complete di un utente.
        Endpoint: POST /v1/user/user-info
        """
        url = f"{self.base_url}/v1/user/user-info"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def forgot_password(self, data: ForgotPasswordRequest) -> dict:
        """
        Avvia il processo di reset della password per un utente.
        Endpoint: POST /v1/user/forgot-password
        """
        url = f"{self.base_url}/v1/user/forgot-password"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def confirm_forgot_password(self, data: ConfirmForgotPasswordRequest) -> dict:
        """
        Completa il reset della password impostando la nuova password.
        Endpoint: POST /v1/user/confirm-forgot-password
        """
        url = f"{self.base_url}/v1/user/confirm-forgot-password"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def refresh_token(self, data: RefreshTokenRequest) -> dict:
        """
        Rinnova i token di accesso tramite il Refresh Token.
        Endpoint: POST /v1/user/refresh-token
        """
        url = f"{self.base_url}/v1/user/refresh-token"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def change_password(self, data: ChangePasswordRequest) -> dict:
        """
        Cambia la password di un utente autenticato.
        Endpoint: POST /v1/user/change-password
        """
        url = f"{self.base_url}/v1/user/change-password"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def verify_user_attribute(self, data: VerifyAttributeRequest) -> dict:
        """
        Invia un codice di verifica per un attributo utente (es. email o phone_number).
        Endpoint: POST /v1/user/verify-user-attribute
        """
        url = f"{self.base_url}/v1/user/verify-user-attribute"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def confirm_user_attribute(self, data: ConfirmAttributeRequest) -> dict:
        """
        Conferma il codice di verifica per un attributo utente (es. email o phone_number).
        Endpoint: POST /v1/user/confirm-user-attribute
        """
        url = f"{self.base_url}/v1/user/confirm-user-attribute"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    # ---------- MFA ENDPOINTS ----------

    def respond_to_mfa_challenge(self, data: MfaRespondChallengeRequest) -> dict:
        """
        Completa il challenge MFA inviando il codice OTP e la session ricevuta.
        Endpoint: POST /v1/user/mfa/respond-challenge

        Args:
            data (MfaRespondChallengeRequest): Dati per rispondere al challenge MFA.

        Returns:
            dict: Risposta di Cognito.
        """
        url = f"{self.base_url}/v1/user/mfa/respond-challenge"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def enable_sms_mfa(self, data: EnableSmsMfaRequest) -> dict:
        """
        Abilita la MFA via SMS per l'utente autenticato.
        Endpoint: POST /v1/user/mfa/enable-sms-mfa

        Args:
            data (EnableSmsMfaRequest): Dati per abilitare SMS MFA.

        Returns:
            dict: Risposta di Cognito.
        """
        url = f"{self.base_url}/v1/user/mfa/enable-sms-mfa"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def disable_sms_mfa(self, data: DisableMfaRequest) -> dict:
        """
        Disabilita la MFA via SMS per l'utente.
        Endpoint: POST /v1/user/mfa/disable-sms-mfa

        Args:
            data (DisableMfaRequest): Dati per disabilitare SMS MFA.

        Returns:
            dict: Risposta di Cognito.
        """
        url = f"{self.base_url}/v1/user/mfa/disable-sms-mfa"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def associate_software_token(self, data: AssociateSoftwareTokenRequest) -> dict:
        """
        Avvia la procedura di associazione di un token software (TOTP).
        Endpoint: POST /v1/user/mfa/associate-software-token

        Args:
            data (AssociateSoftwareTokenRequest): Dati per associare il software token.

        Returns:
            dict: Risposta di Cognito con il SecretCode e la Session.
        """
        url = f"{self.base_url}/v1/user/mfa/associate-software-token"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def verify_software_token(self, data: VerifySoftwareTokenRequest) -> dict:
        """
        Verifica il codice TOTP per completare l'associazione del token software.
        Endpoint: POST /v1/user/mfa/verify-software-token

        Args:
            data (VerifySoftwareTokenRequest): Dati per verificare il software token.

        Returns:
            dict: Risposta di Cognito con lo stato della verifica.
        """
        url = f"{self.base_url}/v1/user/mfa/verify-software-token"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def enable_software_mfa(self, data: AccessTokenOnlyRequest) -> dict:
        """
        Abilita la MFA TOTP (software) come metodo preferito per l'utente.
        Endpoint: POST /v1/user/mfa/enable-software-mfa

        Args:
            data (AccessTokenOnlyRequest): Dati contenenti l'Access Token.

        Returns:
            dict: Risposta di Cognito.
        """
        url = f"{self.base_url}/v1/user/mfa/enable-software-mfa"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    def disable_software_mfa(self, data: AccessTokenOnlyRequest) -> dict:
        """
        Disabilita la MFA TOTP (software) per l'utente.
        Endpoint: POST /v1/user/mfa/disable-software-mfa

        Args:
            data (AccessTokenOnlyRequest): Dati contenenti l'Access Token.

        Returns:
            dict: Risposta di Cognito.
        """
        url = f"{self.base_url}/v1/user/mfa/disable-software-mfa"
        response = requests.post(url, json=data.model_dump(), headers=self.headers)
        response.raise_for_status()
        return response.json()

    # ---------- SOCIAL LOGIN ENDPOINTS ----------

    def social_login_redirect(self, data: SocialLoginRequest) -> str:
        """
        Ottiene l'URL di redirect per il login social.
        Mappa l'endpoint GET /v1/user/social/login-redirect.

        Nota: Per acquisire l'URL di reindirizzamento, disabilitiamo il redirect automatico.

        Args:
            data (SocialLoginRequest): Dati contenenti il nome del provider.

        Returns:
            str: URL di redirect.
        """
        url = f"{self.base_url}/v1/user/social/login-redirect"
        params = data.model_dump()
        response = requests.get(url, params=params, headers=self.headers, allow_redirects=False)
        response.raise_for_status()
        # L'URL di reindirizzamento è presente nell'header "location"
        redirect_url = response.headers.get("location")
        return redirect_url

    def social_login_url(self, data: SocialLoginRequest) -> str:
        """
        Ottiene l'URL per il login social come stringa.
        Mappa l'endpoint GET /v1/user/social/login-url.

        Args:
            data (SocialLoginRequest): Dati contenenti il nome del provider.

        Returns:
            str: URL per il login social.
        """
        url = f"{self.base_url}/v1/user/social/login-url"
        params = data.model_dump()
        response = requests.get(url, params=params, headers=self.headers)
        response.raise_for_status()
        return response.json()["login_url"]

    def social_callback(self, data: SocialCallbackRequest) -> dict:
        """
        Scambia il codice di autorizzazione per i token OAuth2.
        Mappa l'endpoint GET /v1/user/social/callback.

        Args:
            data (SocialCallbackRequest): Dati contenenti il codice e, opzionalmente, lo state.

        Returns:
            dict: Token (AccessToken, IdToken, RefreshToken) restituiti da Cognito.
        """
        url = f"{self.base_url}/v1/user/social/callback"
        params = data.model_dump(exclude_unset=True)
        response = requests.get(url, params=params, headers=self.headers)
        response.raise_for_status()
        return response.json()

