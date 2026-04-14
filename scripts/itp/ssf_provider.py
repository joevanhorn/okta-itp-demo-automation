"""
SSF (Shared Signals Framework) Provider for Okta ITP Demo
==========================================================

Overview
--------
The Shared Signals Framework (SSF) is an OpenID Foundation specification that
enables identity providers and security vendors to exchange real-time security
signals. It builds on top of RFC 8417 (Security Event Token, or SET), which
defines a JWT-based format for conveying security events between parties.

How Okta Uses SSF
-----------------
Okta's Identity Threat Protection (ITP) supports receiving SETs from external
"security events providers." When Okta receives a valid SET, it:
  1. Verifies the JWT signature against the provider's published JWKS
  2. Logs a "Security events provider reported risk" entry in the system log
  3. Updates the user's entity risk score
  4. Triggers any configured Entity Risk Policy rules (e.g., force re-auth,
     terminate sessions, block access)

This allows third-party security tools (SIEMs, CASBs, EDRs) to feed risk
signals into Okta's risk engine. In this demo, WE are the third-party provider.

The SSF Flow (Key Generation -> Signal Delivery)
-------------------------------------------------
  1. **Key Generation**: Generate an RSA-2048 key pair. The private key signs
     SETs; the public key is published as a JWKS so Okta can verify signatures.

  2. **JWKS Hosting**: Upload the public JWKS to a publicly-accessible URL
     (S3, Lambda Function URL, etc.). Okta fetches this to verify SET signatures.

  3. **Provider Registration**: Call Okta's `/api/v1/security-events-providers`
     to register our issuer URI and JWKS URL. This tells Okta to trust SETs
     from this issuer.

  4. **SET Construction**: Build a JWT following RFC 8417 format, containing an
     `events` claim with Okta's `user-risk-change` event type, targeting a
     specific user by email.

  5. **SET Signing**: Sign the JWT with our RSA private key using RS256.

  6. **Signal Delivery**: POST the signed JWT to Okta's
     `/security/api/v1/security-events` endpoint. This endpoint is
     SELF-AUTHENTICATING -- the JWT signature itself proves identity. No
     SSWS API token is needed for this call.

How SSF Mode Differs from Quick and Real Modes
-----------------------------------------------
  - **Quick mode**: Uses Okta's admin API (`PUT /api/v1/users/{id}/risk`)
    directly. Instant, but requires an API token and is clearly an admin
    action in the logs -- not realistic for demos showing third-party signals.

  - **Real mode**: Performs an actual session hijacking simulation using
    Playwright (headless browser auth) + Lambda (cookie replay from a
    foreign IP/region). This triggers Okta's built-in anomaly detection.
    Most realistic, but requires infrastructure (Lambda, SSM secrets).

  - **SSF mode** (this module): Sends a cryptographically signed security
    event signal, mimicking what a real third-party security tool would do.
    Demonstrates the SSF/SET integration point without needing session
    hijacking infrastructure. Requires one-time provider registration and
    key management (stored in SSM).

Usage as module:
    from itp.ssf_provider import SSFProvider

    provider = SSFProvider(org_name="taskvantage", base_url="okta.com",
                           api_token="...", issuer="https://my-issuer",
                           private_key_pem="...", key_id="my-key-id")
    result = provider.send_risk_signal("user@example.com", risk_level="HIGH")
"""

import json
import time
import uuid
import requests

# PyJWT -- used to encode (sign) the Security Event Token as a JWT
import jwt
# cryptography -- used to generate RSA key pairs for SET signing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class SSFProvider:
    """Manages SSF security events provider registration and signal sending.

    This class encapsulates the full lifecycle:
      - RSA key pair generation (for SET signing/verification)
      - Provider registration with Okta's security-events-providers API
      - SET (Security Event Token) construction per RFC 8417
      - JWT signing with RS256
      - Signal delivery to Okta's self-authenticating security events endpoint
      - One-time setup with S3 (JWKS hosting) and SSM (secret storage)
    """

    # Okta's proprietary SET event type URI for user risk level changes.
    # This is the event type Okta recognizes for updating a user's risk score
    # via SSF. It is NOT part of the IETF/OpenID SET standard -- it is
    # Okta-specific.
    RISK_EVENT_TYPE = "https://schemas.okta.com/secevent/okta/event-type/user-risk-change"

    def __init__(self, org_name: str, base_url: str, api_token: str,
                 issuer: str = None, private_key_pem: str = None,
                 key_id: str = None):
        """Initialize the SSF provider client.

        Args:
            org_name: Okta org subdomain (e.g., "taskvantage")
            base_url: Okta domain suffix (e.g., "okta.com" or "oktapreview.com")
            api_token: Okta SSWS API token -- used ONLY for provider registration
                       and management. NOT used for sending SETs (those are
                       self-authenticating via JWT signature).
            issuer: The issuer URI registered with Okta. Must match the "iss"
                    claim in every SET we send. Set during setup() or loaded
                    from SSM.
            private_key_pem: PEM-encoded RSA private key for signing SETs.
            key_id: The "kid" (Key ID) matching the key in our published JWKS.
                    Included in the JWT header so Okta knows which key to use
                    for verification.
        """
        self.org_name = org_name
        self.base_url = base_url
        # Full Okta org URL -- used as the audience ("aud") claim in SETs
        self.okta_url = f"https://{org_name}.{base_url}"
        self.api_base = f"{self.okta_url}/api/v1"
        self.api_token = api_token

        # Standard headers for Okta Admin API calls (provider CRUD operations).
        # The SSWS token authenticates these management API calls.
        self.headers = {
            "Authorization": f"SSWS {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Persistent session for connection pooling on admin API calls
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        # SSF-specific config -- populated either by:
        #   (a) setup() during initial one-time registration, or
        #   (b) constructor args when loaded from SSM via get_ssf_config_from_ssm()
        self.issuer = issuer
        self.private_key_pem = private_key_pem
        self.key_id = key_id

    # =========================================================================
    # Key Generation
    # =========================================================================
    # RSA key pair generation for JWT signing. The private key stays secret
    # (stored in SSM); the public key is published as a JWKS document so Okta
    # can verify our SET signatures.
    # =========================================================================

    @staticmethod
    def generate_keypair():
        """Generate an RSA 2048-bit key pair and derive a JWKS document.

        RSA-2048 with RS256 is the standard signing algorithm for SETs. Okta
        requires the public key to be available as a JWKS (JSON Web Key Set)
        at a publicly-accessible URL.

        Returns:
            tuple: (private_key_pem: str, public_jwks: dict, key_id: str)
                - private_key_pem: PEM-encoded PKCS8 private key for signing
                - public_jwks: JWKS document containing the public key
                - key_id: Unique "kid" identifier for this key
        """
        # Generate a unique key ID. The "kid" appears in both the JWKS and the
        # JWT header, allowing Okta to match the signing key when verifying.
        key_id = f"ssf-demo-{uuid.uuid4().hex[:8]}"

        # Generate RSA-2048 key pair. 65537 is the standard public exponent.
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Export private key as PEM (PKCS8 format, unencrypted).
        # This will be stored in SSM Parameter Store as a SecureString.
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Extract the public key components to build a JWKS document.
        # JWKS (JSON Web Key Set) is the standard format for publishing
        # public keys (RFC 7517). Okta fetches this from our jwks_url to
        # verify SET signatures.
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        def _int_to_base64url(n, length=None):
            """Convert a Python integer to base64url-encoded bytes.

            JWKS requires the RSA modulus (n) and exponent (e) as
            base64url-encoded big-endian unsigned integers, per RFC 7518.
            """
            import base64
            byte_length = length or (n.bit_length() + 7) // 8
            n_bytes = n.to_bytes(byte_length, byteorder="big")
            # base64url encoding omits padding (=) per RFC 7515
            return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("ascii")

        # Build the JWKS document (RFC 7517 format)
        jwks = {
            "keys": [
                {
                    "kty": "RSA",           # Key type: RSA
                    "use": "sig",           # Key usage: signing (not encryption)
                    "alg": "RS256",         # Algorithm: RSASSA-PKCS1-v1_5 with SHA-256
                    "kid": key_id,          # Key ID: matches JWT header "kid"
                    "n": _int_to_base64url(public_numbers.n, 256),  # RSA modulus (256 bytes = 2048 bits)
                    "e": _int_to_base64url(public_numbers.e),       # RSA public exponent
                }
            ]
        }

        return private_key_pem, jwks, key_id

    # =========================================================================
    # Provider Registration
    # =========================================================================
    # These methods manage the security events provider lifecycle in Okta.
    # A provider must be registered before Okta will accept SETs from it.
    # Registration tells Okta: "trust JWTs with this issuer, verified by
    # keys at this JWKS URL."
    # =========================================================================

    def register_provider(self, name: str, issuer: str, jwks_url: str):
        """Register a security events provider with Okta.

        This creates a trust relationship: Okta will accept SETs whose "iss"
        claim matches the registered issuer, verified against keys fetched
        from the registered JWKS URL.

        Uses the Okta Admin API (requires SSWS token).

        Args:
            name: Human-readable display name for the provider (shown in
                  Okta Admin Console under Security > Identity Threat Protection)
            issuer: Issuer URI -- must EXACTLY match the "iss" claim in all
                    SETs sent by this provider
            jwks_url: Publicly-accessible URL to the JWKS document containing
                      the public key(s) for verifying SET signatures

        Returns:
            dict: Provider registration response from Okta, including the
                  assigned provider "id"
        """
        url = f"{self.api_base}/security-events-providers"
        payload = {
            "name": name,
            "type": "ssf",  # Provider type: Shared Signals Framework
            "settings": {
                "issuer": issuer,       # Must match "iss" in SETs
                "jwks_url": jwks_url,   # Where Okta fetches our public key
            },
        }

        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

    def list_providers(self):
        """List all registered security events providers.

        Useful for verifying registration state or finding provider IDs
        for cleanup/deletion.
        """
        url = f"{self.api_base}/security-events-providers"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def delete_provider(self, provider_id: str):
        """Delete a security events provider by ID.

        Removes the trust relationship. Okta will reject SETs from this
        issuer after deletion.
        """
        url = f"{self.api_base}/security-events-providers/{provider_id}"
        response = self.session.delete(url)
        response.raise_for_status()

    # =========================================================================
    # SET (Security Event Token) Building and Signing
    # =========================================================================
    # SETs are defined in RFC 8417. They are JWTs with a specific structure:
    #   - Standard JWT claims (iss, jti, iat, aud)
    #   - An "events" claim containing one or more event payloads
    #   - Content type "secevent+jwt" (not the usual "JWT")
    #
    # Okta extends the RFC 8417 base with proprietary fields inside the event
    # payload (event_timestamp, initiating_entity, reason_admin, etc.).
    # =========================================================================

    def build_set(self, subject_email: str, risk_level: str = "HIGH",
                  reason: str = "Critical security activity detected"):
        """Build a Security Event Token (SET) payload per RFC 8417.

        Constructs the JWT claims for a user-risk-change event. The payload
        is not yet signed -- call sign_set() next.

        Reference:
            - RFC 8417: Security Event Token (SET)
            - Okta docs: https://help.okta.com/oie/en-us/content/topics/itp/configure-shared-signal-provider.htm

        Args:
            subject_email: Email of the user whose risk level to change.
                           Okta resolves this to a user via the primary email.
            risk_level: "HIGH" or "LOW". HIGH triggers entity risk policies;
                        LOW clears the risk (useful for auto-reset after demo).
            reason: Human-readable reason string. Appears in the Okta system
                    log entry for the event.

        Returns:
            dict: SET payload ready for signing. Contains all RFC 8417
                  required claims plus Okta-specific event fields.
        """
        now = int(time.time())
        # Okta requires both current and previous risk levels in the event.
        # We infer the previous level as the opposite of the requested level.
        previous_level = "low" if risk_level.upper() == "HIGH" else "high"

        payload = {
            # --- RFC 8417 Standard JWT Claims ---

            # "iss" (Issuer): Identifies WHO is sending this SET.
            # Must exactly match the issuer registered with Okta's
            # security-events-providers API.
            "iss": self.issuer,

            # "jti" (JWT ID): Unique identifier for this specific SET.
            # Prevents replay attacks -- Okta rejects duplicate jti values.
            "jti": str(uuid.uuid4()),

            # "iat" (Issued At): Unix timestamp when this SET was created.
            # Okta may reject SETs with timestamps too far in the past.
            "iat": now,

            # "aud" (Audience): Identifies WHO this SET is intended for.
            # Must be the Okta org URL (e.g., "https://taskvantage.okta.com").
            "aud": self.okta_url,

            # --- RFC 8417 Events Claim ---
            # The "events" object is the core of a SET. Keys are event type
            # URIs; values are the event-specific payloads. A SET can contain
            # multiple events, but typically contains just one.
            "events": {
                # Event type URI -- Okta's proprietary event type for user
                # risk level changes via SSF
                self.RISK_EVENT_TYPE: {
                    # "subject": Identifies the affected user per the SCIM
                    # subject identifier format (RFC 7643).
                    "subject": {
                        "user": {
                            "format": "email",          # Subject format: email
                            "email": subject_email,     # User's primary email in Okta
                        }
                    },
                    # --- Okta-Specific Event Fields ---
                    # These are NOT part of RFC 8417; they are required by
                    # Okta's implementation of the user-risk-change event type.

                    # Unix timestamp of when the risk-triggering event occurred
                    "event_timestamp": now,
                    # Who/what initiated this signal: "admin" = manual/API action
                    "initiating_entity": "admin",
                    # Localized reason string (Okta supports i18n; "en" = English)
                    "reason_admin": {
                        "en": reason,
                    },
                    # The new (current) risk level being reported
                    "current_level": risk_level.lower(),
                    # The previous risk level (before this change)
                    "previous_level": previous_level,
                }
            },
        }
        return payload

    def sign_set(self, payload: dict) -> str:
        """Sign a SET payload as a JWT using RS256.

        The signed JWT is what gets POSTed to Okta. Okta verifies the
        signature by fetching our JWKS (using the "kid" from the JWT header
        to find the right key) and checking the RS256 signature.

        Args:
            payload: SET payload dict (from build_set())

        Returns:
            str: Signed JWT string (compact serialization: header.payload.signature)
        """
        headers = {
            # "typ": Content type for Security Event Tokens per RFC 8417.
            # This distinguishes SETs from regular JWTs.
            "typ": "secevent+jwt",
            # "kid": Key ID matching the key in our published JWKS.
            # Okta uses this to look up the correct public key for
            # signature verification.
            "kid": self.key_id,
        }
        # PyJWT handles: base64url encoding, RS256 signing with the private
        # key, and compact serialization (header.payload.signature).
        return jwt.encode(
            payload,
            self.private_key_pem,
            algorithm="RS256",
            headers=headers,
        )

    # =========================================================================
    # Signal Sending
    # =========================================================================
    # The security events endpoint is SELF-AUTHENTICATING. Unlike most Okta
    # APIs that require an SSWS token or OAuth bearer token, this endpoint
    # authenticates the caller by verifying the JWT signature against the
    # registered provider's JWKS. No additional credentials are needed.
    #
    # This mirrors how real third-party security tools integrate -- they
    # only need their signing key, not an Okta API token.
    # =========================================================================

    def send_signal(self, set_jwt: str):
        """Send a signed SET to Okta's security events endpoint.

        This endpoint is SELF-AUTHENTICATING: the JWT signature IS the
        authentication mechanism. Okta:
          1. Reads the "iss" claim from the JWT
          2. Looks up the registered provider with that issuer
          3. Fetches the JWKS from the provider's registered jwks_url
          4. Verifies the JWT signature using the key matching the "kid" header
          5. If valid, processes the event (updates user risk, logs event)

        No SSWS token or other credential is needed for this call.

        Args:
            set_jwt: Signed SET JWT string (from sign_set())

        Returns:
            dict: {"status": "success", "http_code": 202} on success, or
                  {"status": "error", "http_code": ..., "error": ...} on failure
        """
        url = f"{self.okta_url}/security/api/v1/security-events"
        # Content-Type is "application/secevent+jwt" per the SSF spec --
        # the body is the raw JWT string, NOT JSON-wrapped.
        headers = {
            "Content-Type": "application/secevent+jwt",
            "Accept": "application/json",
        }

        # POST the raw JWT string as the request body.
        # Note: we use requests.post() directly (not self.session) because
        # this endpoint does NOT use the SSWS Authorization header.
        response = requests.post(url, data=set_jwt, headers=headers)

        # 202 Accepted is the standard success response for SET delivery.
        # Some Okta versions may return 200 OK.
        if response.status_code == 202 or response.status_code == 200:
            return {"status": "success", "http_code": response.status_code}

        # Parse error details from Okta's error response
        error_detail = response.text
        try:
            error_json = response.json()
            error_detail = error_json.get("errorSummary", error_detail)
        except Exception:
            pass

        return {
            "status": "error",
            "http_code": response.status_code,
            "error": error_detail,
        }

    def send_risk_signal(self, subject_email: str, risk_level: str = "HIGH"):
        """Build, sign, and send a user risk change signal in one call.

        Convenience method that chains the full pipeline:
            build_set() -> sign_set() -> send_signal()

        This is the primary method called by the demo orchestrator
        (trigger_itp_demo.py) when running in SSF mode.

        Args:
            subject_email: User email to set risk for
            risk_level: "HIGH" or "LOW"

        Returns:
            dict: Result with status, http_code, and jti (for log correlation)
        """
        payload = self.build_set(subject_email, risk_level)
        set_jwt = self.sign_set(payload)
        result = self.send_signal(set_jwt)
        # Include the jti so callers can correlate with Okta system log entries
        result["jti"] = payload["jti"]
        return result

    # =========================================================================
    # One-Time Setup
    # =========================================================================
    # This method performs the full initial registration workflow:
    #   1. Generate RSA key pair
    #   2. Upload JWKS to S3 (public URL for Okta to fetch)
    #   3. Register the provider with Okta
    #   4. Store private key and config in SSM Parameter Store
    #
    # After setup, subsequent runs only need to load config from SSM
    # (via get_ssf_config_from_ssm) -- no re-registration needed.
    # =========================================================================

    def setup(self, name: str, s3_bucket: str,
              s3_key_prefix: str = "ssf-demo",
              aws_region: str = "us-east-1",
              aws_profile: str = None,
              ssm_prefix: str = "/itp-demo/ssf-demo"):
        """Full one-time setup: generate keys, upload JWKS, register provider, store in SSM.

        This is called once per Okta org to establish the SSF trust relationship.
        After running, the private key and provider config are stored in SSM
        so subsequent demo runs can load them without re-registering.

        Args:
            name: Provider display name (shown in Okta Admin Console)
            s3_bucket: S3 bucket for hosting the JWKS document. Must be
                       publicly readable (or use a CloudFront distribution).
            s3_key_prefix: S3 key prefix for the JWKS file (default: "ssf-demo")
            aws_region: AWS region for S3 and SSM operations
            aws_profile: AWS CLI profile name (optional; uses default if None)
            ssm_prefix: SSM Parameter Store path prefix for storing secrets.
                        Two parameters are created:
                          {ssm_prefix}/private-key    (SecureString - RSA private key)
                          {ssm_prefix}/provider-config (String - JSON with issuer, kid, etc.)

        Returns:
            dict: Setup results including provider_id, issuer, jwks_url, key_id,
                  and ssm_prefix
        """
        import boto3

        session_kwargs = {"region_name": aws_region}
        if aws_profile:
            session_kwargs["profile_name"] = aws_profile
        boto_session = boto3.Session(**session_kwargs)

        # Step 1: Generate RSA key pair for SET signing
        print("\n  [1/4] Generating RSA key pair...")
        private_key_pem, jwks, key_id = self.generate_keypair()
        print(f"         Key ID: {key_id}")

        # Step 2: Upload JWKS to S3 so Okta can fetch our public key.
        # The JWKS URL must be publicly accessible -- Okta's servers will
        # HTTP GET this URL to retrieve the public key for signature verification.
        print(f"\n  [2/4] Uploading JWKS to s3://{s3_bucket}/{s3_key_prefix}/jwks.json...")
        s3_client = boto_session.client("s3")
        s3_key = f"{s3_key_prefix}/jwks.json"
        s3_client.put_object(
            Bucket=s3_bucket,
            Key=s3_key,
            Body=json.dumps(jwks, indent=2),
            ContentType="application/json",
        )
        # Construct the public HTTPS URL for the S3-hosted JWKS
        jwks_url = f"https://{s3_bucket}.s3.amazonaws.com/{s3_key}"
        print(f"         JWKS URL: {jwks_url}")

        # Step 3: Register the provider with Okta.
        # The issuer is derived from the S3 bucket URL + prefix. It must be
        # a stable URI that uniquely identifies this provider. All SETs we
        # send will have this as the "iss" claim.
        issuer = f"https://{s3_bucket}.s3.amazonaws.com/{s3_key_prefix}"
        print(f"\n  [3/4] Registering security events provider...")
        print(f"         Name: {name}")
        print(f"         Issuer: {issuer}")
        provider = self.register_provider(name, issuer, jwks_url)
        provider_id = provider.get("id")
        print(f"         Provider ID: {provider_id}")

        # Step 4: Store config in SSM Parameter Store for persistence.
        # This allows subsequent demo runs to load the config without
        # re-registering. Two parameters are stored:
        #   - private-key: The RSA private key (SecureString = encrypted at rest)
        #   - provider-config: JSON with issuer, provider_id, jwks_url, key_id
        print(f"\n  [4/4] Storing configuration in SSM...")
        ssm_client = boto_session.client("ssm")

        # Store private key as SecureString (encrypted with AWS KMS)
        ssm_client.put_parameter(
            Name=f"{ssm_prefix}/private-key",
            Description="SSF Demo - RSA private key for SET signing",
            Value=private_key_pem,
            Type="SecureString",
            Overwrite=True,
        )
        print(f"         Private key: {ssm_prefix}/private-key")

        # Store provider metadata as plaintext JSON (no secrets in this blob)
        config = {
            "issuer": issuer,
            "provider_id": provider_id,
            "jwks_url": jwks_url,
            "key_id": key_id,
            "provider_name": name,
        }
        ssm_client.put_parameter(
            Name=f"{ssm_prefix}/provider-config",
            Description="SSF Demo - Provider configuration",
            Value=json.dumps(config),
            Type="String",
            Overwrite=True,
        )
        print(f"         Config: {ssm_prefix}/provider-config")

        # Update this instance's state so it's ready to send signals
        # immediately after setup (no need to reload from SSM)
        self.issuer = issuer
        self.private_key_pem = private_key_pem
        self.key_id = key_id

        return {
            "provider_id": provider_id,
            "issuer": issuer,
            "jwks_url": jwks_url,
            "key_id": key_id,
            "ssm_prefix": ssm_prefix,
        }


# =============================================================================
# SSM Configuration Loader (Module-Level Helper)
# =============================================================================
# This standalone function loads SSF provider config from AWS SSM Parameter
# Store, allowing scripts to reconstitute an SSFProvider instance without
# re-running the one-time setup.
#
# SSM Parameter Structure:
#   {ssm_prefix}/
#     provider-config   (String)       - JSON containing:
#       {
#         "issuer": "https://...",       - Issuer URI (matches "iss" in SETs)
#         "provider_id": "sep...",       - Okta provider ID (for management)
#         "jwks_url": "https://...",     - Public JWKS URL
#         "key_id": "ssf-demo-...",      - Key ID (matches "kid" in JWT header)
#         "provider_name": "..."         - Human-readable name
#       }
#     private-key       (SecureString) - PEM-encoded RSA private key for signing
# =============================================================================

def get_ssf_config_from_ssm(ssm_prefix: str = "/itp-demo/ssf-demo",
                             region: str = "us-east-2",
                             profile: str = None):
    """Load SSF provider config and private key from AWS SSM Parameter Store.

    This is the counterpart to SSFProvider.setup() -- it retrieves the config
    and private key that setup() stored, so an SSFProvider instance can be
    reconstituted for sending signals without re-registering.

    Typical usage:
        config, private_key_pem = get_ssf_config_from_ssm(profile="taskvantage")
        provider = SSFProvider(
            org_name="taskvantage", base_url="okta.com", api_token="...",
            issuer=config["issuer"],
            private_key_pem=private_key_pem,
            key_id=config["key_id"],
        )

    Args:
        ssm_prefix: SSM parameter path prefix. The function reads two
                    parameters under this prefix:
                      {ssm_prefix}/provider-config  (JSON string)
                      {ssm_prefix}/private-key      (SecureString, decrypted)
        region: AWS region where the SSM parameters are stored
        profile: AWS CLI profile name (optional; uses default if None)

    Returns:
        tuple: (config_dict, private_key_pem)
            - config_dict: Parsed JSON with issuer, provider_id, jwks_url,
                           key_id, provider_name
            - private_key_pem: Decrypted PEM-encoded RSA private key string
    """
    import boto3

    session_kwargs = {"region_name": region}
    if profile:
        session_kwargs["profile_name"] = profile
    boto_session = boto3.Session(**session_kwargs)
    ssm = boto_session.client("ssm")

    # Get provider config (stored as plaintext JSON String)
    config_resp = ssm.get_parameter(
        Name=f"{ssm_prefix}/provider-config",
    )
    config = json.loads(config_resp["Parameter"]["Value"])

    # Get private key (stored as SecureString, encrypted with KMS).
    # WithDecryption=True tells SSM to decrypt the value before returning it.
    key_resp = ssm.get_parameter(
        Name=f"{ssm_prefix}/private-key",
        WithDecryption=True,
    )
    private_key_pem = key_resp["Parameter"]["Value"]

    return config, private_key_pem
