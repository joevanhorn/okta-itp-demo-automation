#!/usr/bin/env python3
"""
setup_ssf_provider.py

One-time, post-Terraform setup for the SSF (Shared Signals Framework) security
events provider used in the ITP demo's "SSF mode."

Background:
  The Shared Signals Framework (RFC 8935 / OpenID SSF) lets external systems
  push security-event tokens (SETs) to Okta to influence a user's risk score.
  For this to work, Okta must trust the JWT issuer -- which means the issuer's
  JWKS endpoint and issuer URI must be registered as a "security events
  provider" in the Okta org.

  Terraform creates the *infrastructure* (a Lambda-backed JWKS endpoint, an RSA
  key pair, and SSM parameters that store the config), but it cannot call the
  Okta security-events-provider API because the Okta Terraform provider does
  not support that resource.  This script bridges the gap.

Workflow (run once per environment):
  1. ``terraform apply`` creates Lambda, RSA key, and writes JWKS URL / issuer /
     key_id into an SSM parameter at ``<prefix>/provider-config``.
  2. This script reads that SSM parameter (step 1/3).
  3. It POSTs the provider details to Okta's
     ``/api/v1/security-events-providers`` endpoint (step 2/3).
  4. Okta returns a ``provider_id`` (e.g., ``sepXXXXXX``); this script writes
     that ID back into the same SSM parameter so that ``trigger_itp_demo.py``
     can reference it later (step 3/3).

  If the provider is already registered (``provider_id`` in SSM is not
  ``pending-registration``), the script exits cleanly.

Additional operations:
  --list    Enumerate all registered security events providers in the org.
  --delete  Remove a provider by ID (useful for re-registration).

Prerequisites:
  - Run ``terraform apply`` first to create the Lambda JWKS endpoint, RSA key
    pair, and SSM parameters.
  - OKTA_ORG_NAME, OKTA_API_TOKEN environment variables (or CLI flags).
  - AWS credentials with SSM read/write access to the parameter prefix.

Usage:
    # Register provider with Okta (reads config from SSM)
    python3 scripts/setup_ssf_provider.py

    # List existing providers
    python3 scripts/setup_ssf_provider.py --list

    # Delete a provider
    python3 scripts/setup_ssf_provider.py --delete --provider-id sep1234567890
"""

import os
import sys
import json
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Register SSF security events provider with Okta (post-Terraform)"
    )
    parser.add_argument(
        "--org-name",
        default=os.environ.get("OKTA_ORG_NAME"),
        help="Okta organization name",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("OKTA_BASE_URL", "okta.com"),
        help="Okta base URL",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("OKTA_API_TOKEN"),
        help="Okta API token",
    )

    # SSM config -- the prefix under which Terraform wrote the provider config.
    # Override this if your Terraform workspace uses a different parameter path.
    parser.add_argument(
        "--ssm-prefix",
        default=os.environ.get("SSF_SSM_PREFIX", "/itp-demo/ssf-demo"),
        help="SSM parameter path prefix (default: $SSF_SSM_PREFIX or /itp-demo/ssf-demo)",
    )
    parser.add_argument(
        "--provider-name",
        default="ITP Demo Signal Source",
        help="Display name for the provider in Okta",
    )
    parser.add_argument(
        "--aws-region",
        default="us-east-2",
        help="AWS region for SSM (default: us-east-2)",
    )
    parser.add_argument(
        "--aws-profile",
        default=os.environ.get("AWS_PROFILE"),
        help="AWS CLI profile name",
    )

    # Alternative actions
    parser.add_argument(
        "--list",
        action="store_true",
        help="List existing security events providers",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete a security events provider",
    )
    parser.add_argument(
        "--provider-id",
        help="Provider ID (for --delete)",
    )

    args = parser.parse_args()

    if not args.org_name or not args.api_token:
        print("Error: OKTA_ORG_NAME and OKTA_API_TOKEN must be set")
        sys.exit(1)

    # Defer the import so that missing boto3/requests do not crash before we
    # can show a helpful "missing args" error above.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, script_dir)
    from itp.ssf_provider import SSFProvider

    # SSFProvider wraps the Okta /api/v1/security-events-providers endpoints.
    provider = SSFProvider(
        org_name=args.org_name,
        base_url=args.base_url,
        api_token=args.api_token,
    )

    # --- List providers ---
    # Useful for verifying registration or finding a provider_id before delete.
    if args.list:
        print("Registered Security Events Providers:")
        print("-" * 60)
        providers = provider.list_providers()
        if not providers:
            print("  (none)")
        for p in providers:
            settings = p.get("settings", {})
            print(f"  ID:     {p.get('id')}")
            print(f"  Name:   {p.get('name')}")
            print(f"  Type:   {p.get('type')}")
            print(f"  Issuer: {settings.get('issuer')}")
            print(f"  JWKS:   {settings.get('jwks_url')}")
            print()
        sys.exit(0)

    # --- Delete provider ---
    # Removing a provider deregisters the issuer from Okta; any SETs signed by
    # its key will be rejected after deletion.
    if args.delete:
        if not args.provider_id:
            print("Error: --provider-id is required with --delete")
            sys.exit(1)
        print(f"Deleting provider: {args.provider_id}...")
        provider.delete_provider(args.provider_id)
        print("  Done.")
        sys.exit(0)

    # --- Register with Okta (post-Terraform) ---
    # This is the primary code path: read config from SSM, register with Okta,
    # then write the Okta-assigned provider_id back to SSM.
    print("=" * 60)
    print("SSF PROVIDER REGISTRATION (Post-Terraform)")
    print("=" * 60)
    print(f"  Okta org:  {args.org_name}.{args.base_url}")
    print(f"  SSM path:  {args.ssm_prefix}")

    try:
        import boto3

        session_kwargs = {"region_name": args.aws_region}
        if args.aws_profile:
            session_kwargs["profile_name"] = args.aws_profile
        boto_session = boto3.Session(**session_kwargs)
        ssm = boto_session.client("ssm")

        # Step 1: Read the provider-config JSON from SSM.  Terraform populates
        # this with jwks_url, issuer, key_id, and a placeholder provider_id of
        # "pending-registration".
        print("\n  [1/3] Reading provider config from SSM...")
        config_resp = ssm.get_parameter(Name=f"{args.ssm_prefix}/provider-config")
        config = json.loads(config_resp["Parameter"]["Value"])

        jwks_url = config["jwks_url"]
        issuer = config["issuer"]
        key_id = config["key_id"]

        print(f"         JWKS URL: {jwks_url}")
        print(f"         Issuer:   {issuer}")
        print(f"         Key ID:   {key_id}")

        # Guard against double-registration.  If provider_id is already set to
        # something other than the placeholder, the provider was registered in
        # a previous run and we can exit safely.
        if config.get("provider_id") and config["provider_id"] != "pending-registration":
            print(f"\n  Provider already registered: {config['provider_id']}")
            print("  Use --delete to remove and re-register if needed.")
            sys.exit(0)

        # Step 2: Register with Okta via POST /api/v1/security-events-providers
        print(f"\n  [2/3] Registering with Okta...")
        result = provider.register_provider(
            name=args.provider_name,
            issuer=issuer,
            jwks_url=jwks_url,
        )
        provider_id = result.get("id")
        print(f"         Provider ID: {provider_id}")

        # Step 3: Write the Okta-assigned provider_id back to SSM so that
        # trigger_itp_demo.py (SSF mode) can look it up at runtime.
        print(f"\n  [3/3] Updating SSM config with provider ID...")
        config["provider_id"] = provider_id
        config["provider_name"] = args.provider_name
        ssm.put_parameter(
            Name=f"{args.ssm_prefix}/provider-config",
            Value=json.dumps(config),
            Type="String",
            Overwrite=True,
        )
        print(f"         Updated: {args.ssm_prefix}/provider-config")

        print("\n" + "=" * 60)
        print("REGISTRATION COMPLETE")
        print("=" * 60)
        print(f"  Provider ID: {provider_id}")
        print(f"  Issuer:      {issuer}")
        print(f"  JWKS URL:    {jwks_url}")
        print()
        print("Test with:")
        print("  python3 scripts/trigger_itp_demo.py --mode ssf \\")
        print("    --user <email> --risk-level HIGH --monitor")

    except Exception as e:
        print(f"\nRegistration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
