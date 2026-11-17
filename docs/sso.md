# Single sign-on from the panel

When sign-in is managed in the app (`AUTH_PROVIDER` unset), the owner connects an OpenID Connect
provider under **Admin → Sign-in**. (With `AUTH_PROVIDER=oidc` the connection comes from the
`OIDC_*` variables instead, as described in [authentication.md](authentication.md); the panel then
shows it read-only.)

## How it works, and why it cannot lock you out

1. **Start** a draft from a preset (Google, Microsoft, Okta, Keycloak or any other OpenID Connect
   provider) and fill in the form. Saving a draft changes nothing for anyone.
2. **Register the redirect URI** shown on the page with the provider:
   `https://<your APP_URL>/auth/callback`.
3. **Test sign-in.** This opens a new window and runs a real sign-in against the draft. You see
   what the provider sent back (the identity claims, never tokens) and which rule would let that
   person in. The test does not change your session and does not create users.
4. **Activate.** This is possible only after a test of the draft *as currently saved* passed,
   within the last 24 hours. The sign-in page then offers "Sign in with …" on every instance
   within a few seconds.

The owner's password + authenticator sign-in is always available, whatever is configured. If
the provider breaks later (secret expired, provider down), only the button fails: sign in as the
owner, then fix the connection or deactivate it. Activating, replacing or deactivating a
connection does not end anyone's session.

### Who gets in

A person signing in through the connection is admitted like everyone else: by their assigned role,
an invitation, or an access rule (**Admin → Access rules**). Anyone else becomes a pending
request. The address is read from exactly one claim. With the standard `email` claim, the
provider must state `email_verified: true`. **Required claims** (`claim=value`, comma-separated,
`|` between alternatives) refuse a sign-in before any rule is looked at; use them to pin a shared
provider to your organization.

### Password sign-in switches

- **Password sign-in for non-owners**: lets people other than the owner who have a password and
  authenticator use the password form (in practice a former owner). Off by default.
- **Require single sign-on**: while a connection is active, everyone but the owner must use it,
  and the sign-in page shows the password form only behind "Owner sign-in". With no active
  connection it has no effect, so it cannot leave people without a way in.

Both can also be set with `AUTH_LOCAL_SIGNIN_NON_OWNERS` and `AUTH_ENFORCE_SSO`.

## Google (Google Workspace)

1. In the Google Cloud console, open the **Branding** page and set up the consent screen for a
   project (for a Workspace, limit it to users in your organization).
2. On the **Clients** page, **Create client** of type *Web application*. Add the redirect URI
   under **Authorized redirect URIs**. It must match exactly: scheme, case and any trailing `/`.
3. Copy the client ID and client secret into the draft. Issuer: `https://accounts.google.com`.
4. **Required claims: `hd=<your Workspace domain>`.** Google signs in *any* Google account. The
   `hd` claim names the Workspace a person belongs to, and is absent for personal accounts. It is
   what restricts sign-in to your organization; the preset fills it in for you to complete.
5. Google sends no groups: use email-domain rules or invitations.

## Microsoft Entra ID

1. In the Microsoft Entra admin center, go to **Entra ID → App registrations → New
   registration**. Supported account types: **Single tenant only**. Add the redirect URI as a
   *Web* redirect URI, on the registration form or afterwards on the app's **Authentication**
   page.
2. From the app's **Overview**, copy the **Application (client) ID** and the **Directory (tenant)
   ID**. Issuer: `https://login.microsoftonline.com/<tenant ID>/v2.0`.
3. **Certificates & secrets → Client secrets → New client secret.** Copy the secret's **Value**
   (it is shown only once). Microsoft limits a secret to 24 months and recommends less than 12:
   note the expiry date, and replace the secret in the draft (test, activate) before it runs out.
4. Email claim: **`preferred_username`** (the preset sets it). Entra sends no `email_verified`,
   and its `email` claim is an editable attribute, so it is not used to identify people.
5. Optional, for group rules: **Token configuration → Add groups claim**. Entra sends group
   **object IDs**: write those IDs in the group rules.

## Okta

1. In the Admin Console, go to **Applications → Applications → Create App Integration**, choose
   **OIDC - OpenID Connect** and **Web Application**.
2. Under **Sign-in redirect URIs**, enter the redirect URI. Under **Assignments**, choose who may
   use the app.
3. From the **General** tab, copy the client ID, and the client secret (client authentication:
   *Client secret*).
4. Issuer: `https://<your org>.okta.com` (the org authorization server), or
   `https://<your org>.okta.com/oauth2/default` for the default custom authorization server.
5. For group rules, add a `groups` claim to the ID token (a groups claim filter on the app, or a
   claim on the custom authorization server) and keep the `groups` scope.

## Keycloak

1. In the realm, **Clients → Create client**: client type *OpenID Connect*, a client ID, then
   turn **Client authentication** on (a confidential client). Enter the redirect URI under **Valid
   redirect URIs**.
2. Copy the secret from the client's **Credentials** tab. Issuer:
   `https://<keycloak host>/realms/<realm>`.
3. For group rules, open the client's dedicated scope (**Client scopes** tab → the dedicated
   scope) → **Add mapper → By configuration → Group Membership**, with token claim name `groups`
   and "Add to ID token" on.
4. **Keep "Full group path" on** and write group rules with the full path, for example
   `/dmarc-admins`. Without it, a group's short name can match a same-named group elsewhere in the
   tree. Keycloak's own upgrade notes for 26.8 make the same recommendation for nested groups.

## Any other OpenID Connect provider

Use the issuer shown in the provider's settings. Its discovery document must be served at
`<issuer>/.well-known/openid-configuration`, and the `issuer` inside it must match exactly. Register
the redirect URI, use the authorization-code flow with a client secret (or none, for a public
client using PKCE), and include `openid` in the scopes.

## When the test fails

| Error | Usual cause |
|---|---|
| `discovery` | The issuer URL is wrong (it must be the exact issuer), or this server cannot reach it. |
| `provider: redirect_uri_mismatch` | The redirect URI is not registered with the provider, or differs in scheme, host, case or a trailing `/`. |
| `provider: invalid_client`, `exchange` | Wrong client ID or client secret. |
| `unverified_email` | The provider does not state the address is verified. For Entra use `preferred_username`. |
| `no_email` | The email claim is missing: check the claim name and the scopes. |
| `wrong_account` | A required claim is missing or has another value (for Google: the account is not in your Workspace). |
