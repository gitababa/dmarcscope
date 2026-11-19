# Enterprise access: domain permissions, SCIM, API tokens

Three things for larger organizations, all optional and all off until an administrator uses them:
limiting people to chosen domains, provisioning people from your identity provider (SCIM 2.0), and
read-only API tokens with CSV export. Upgrading changes nothing for anyone: everybody keeps
seeing what they saw.

## Domain permissions

Only **viewers** can be limited. Administrators and owners manage mail, domains, alerts and people
for the whole deployment, so they always see every domain; making a limited viewer an
administrator lifts the limit.

A viewer's domains are worked out on every request, in this order:

1. Their **own setting** (Admin → Users → the person → *Domain access*) wins: *every domain*, or
   *only these* (their domains plus those of the limited groups they are in).
2. With no setting of their own: a group set to *every domain* gives everything, otherwise the
   limited groups' domains are combined.
3. With no setting anywhere: **Settings → Domains a viewer sees without a scope**
   (`ACCESS_DOMAIN_DEFAULT`), `all` by default and `none` if an owner chooses it.

A limited setting with no domains lets the person see **nothing**, never everything. A domain
may be listed before its first report arrives.

**Choose `none` once you limit groups.** A group is a name in your identity provider's group claim
(the claim you configured under Admin → Sign-in) or a SCIM group. If the identity provider ever
stops sending groups, a viewer then belongs to no group and, with the default `all`, would see
everything. With `none` they see nothing until it is fixed. **Admin → Groups** says so while it
applies.

What a limited person sees: only their domains on Overview, Issues, each domain page, the CSV
downloads and the API. A domain outside their scope answers "not found", exactly like one that does
not exist. The ingest history on Overview is empty for them: its counts would show other domains'
volume.

Changes apply on the person's next request on every instance.

## SCIM provisioning

Point your identity provider's SCIM client at `https://<your app>/scim/v2` with a bearer token from
**Admin → API access** (owners only; creating a new one ends the old). Supported: `Users` and
`Groups` (list with `filter` `userName eq`, `externalId eq`, `displayName eq`; get; create; replace;
patch; delete), `ServiceProviderConfig`, `ResourceTypes`, `Schemas`.

What SCIM can and cannot do, on purpose:

- It creates **viewers**. It cannot set or change a role (`roles`, `entitlements` and `password` are
  refused).
- It cannot touch an **owner**: every operation on one answers 403.
- It cannot change a `userName` (the e-mail address is the identity; a rename could hand an
  administrator's account to someone else).
- `active: false` and `DELETE` **deactivate** immediately: the person is disabled and signed out, and
  their next request is refused. `DELETE` also removes them from every group. Re-activate with
  `active: true`.
- SCIM groups count for **domain scopes only**. They never feed access rules, so a group named like
  an administrators group cannot grant a role.

Request bodies are limited to 256 KB and group member lists to 1000. Every change is in the audit
log as `scim:<token name>`.

Not verified against a real Okta or Entra ID tenant: the endpoints were exercised with a test
client. Entra's quirks (boolean strings such as `"False"`, patch paths such as
`emails[type eq "work"].value`) are handled; report anything else you meet.

## API tokens

**Admin → API access → New API token.** A token has a name, scopes, domains and an expiry (1 to 365
days, default 90). It is shown **once**; only its SHA-256 is stored.

| Scope | Allows |
| --- | --- |
| `domains:read` | `/api/v1/domains`, `/api/v1/domains/{domain}/summary`, `.../timeseries` |
| `reports:read` | `/api/v1/domains/{domain}/sources`, `/api/v1/problems` |
| `dns:read` | `/api/v1/domains/{domain}/dns` |

```bash
curl -H "Authorization: Bearer $TOKEN" "https://dmarc.example.com/api/v1/domains?days=30"
curl -H "Authorization: Bearer $TOKEN" "https://dmarc.example.com/api/v1/problems?days=30&format=csv"
```

`days` is 1 to 90 (default 7). Add `format=csv` for a spreadsheet; cells that would run as a formula
are neutralized. Errors are JSON, `{"error": {"code", "message"}}`.

- Only the header is read: not a cookie, and not a token in a URL.
- A token is read-only and never wider than its creator: it stops working at once if the person who
  made it is disabled, removed, or no longer an administrator.
- Unknown, expired, revoked and malformed tokens all answer the same `401`.
- A token limited to no domains sees nothing; a domain outside its scope is a `404`.
- Revoke a token on the same screen. Administrators create tokens; the SCIM token is the owner's.

Signed-in people can also download CSV from the domain page (sources, volume per day) and the
Issues page, limited to the domains they may see.

## Upgrading

Run the migrations (`0008`). Nothing is limited, no token or SCIM user exists, and the new screens
(Admin → Groups, Admin → API access) are empty.
