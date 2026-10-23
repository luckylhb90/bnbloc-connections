# bnbloc-connections

The **connections** component for [bnbloc](https://github.com/luckylhb90/bnbloc):
a member's own agents reach the systems the member connected (a wiki, an
issue tracker, a calendar, a code host), **as the member**, with ordinary
HTTPS. The agent gets nothing new: it calls the system with `curl`, a script
or a CLI, and each request is authenticated on its way out, where the agent
never sees the credential. Reads go through; a change asks the member first
unless they allowed changes for that system; every call is recorded.

It is a bnbloc **service component** (`bnbloc.service.package/v1`; the
platform side is `docs/architecture/service-components.md` in bnbloc) and
uses the primitives it declares: `turnProxy`, `egress`, `roomFacts`,
`pages`, `callbacks`, `store`. Design: `docs/prd/2026-10-22-connections.md`
in bnbloc.

```
agent's command ──HTTPS──▶ bridge egress proxy (local CA, claimed hosts only)
   ──turn proxy (job attested)──▶ gateway ──signed──▶ bnbloc-connections
   ──the member's credential──▶ the system
```

## What a member sees

- **Components → Connections → Open**: each system the organization
  enabled, connected or not, with Connect (OAuth sign-in, a pasted key, or
  the organization's provider), Allow changes / Ask me for changes,
  Disconnect (revoked at the provider), and the recent calls.
- **A card in the room** the first time their agent tries a system that is
  not connected (Connect, Ask again), and for every change not allowed in
  advance (Review → Allow / Don't allow, optionally "without asking from
  now on"). Only they see it.

## What the agent sees

- One line in its room records: `connections/: systems you reach as maya
  with plain HTTPS (curl, scripts, CLIs): wiki, issues; INDEX.md says what
  each is for`.
- Files under `.room/connections/`, read when a task needs them: `INDEX.md`
  (each system, its hosts, connected or not, changes asked or allowed),
  `<system>.md` (its guide with curl examples), `ACTIVITY.md` (the person's
  recent calls in this room), `DRAFTING.md` (how to draft a connector).
- Refusals are ordinary HTTP: `403` with JSON (not connected: the person
  was asked), `202` `held` (a change waits for the person), `429` (slow
  down).
- Its own API at `https://connections.bnbloc/` (through the same proxy):
  `GET /systems`, `GET /activity?room=`, `POST /drafts`.

Only the person's **own** agent (or a schedule they created) is served:
the platform attests the drive, and a borrowed or platform agent gets no
hosts, no facts and a `403`.

## Connectors

A connector is one system, and an organization's content: an org admin
adds, edits, enables and removes them on **Components → Connectors**
(samples: [bnbloc-connectors](https://github.com/luckylhb90/bnbloc-connectors)),
and reviews the drafts agents post there.

```json
{
  "name": "issues",
  "displayName": "Issue tracker",
  "purpose": "Bugs and tasks",
  "hosts": ["issues.example.com"],
  "connect": {"kind": "apiKey", "apiKey": {"in": "bearer", "help": "Profile → Tokens"}},
  "policy": {
    "read": [{"paths": ["/api/**"]}, {"methods": ["POST"], "paths": ["/api/search"], "body": "^\\s*\\{"}],
    "write": [{"methods": ["POST", "PUT", "PATCH", "DELETE"], "paths": ["/api/**"]}]
  },
  "expiredWhen": [{"status": 302, "locationContains": "/login"}],
  "cliEnv": {"ISSUES_TOKEN": "connected"},
  "guide": "curl https://issues.example.com/api/issue/PROJ-1"
}
```

- `hosts`: exact names; only these are intercepted.
- `connect.kind`:
  - `oauth2`: authorization code with PKCE; `issuer` (RFC 8414 / OIDC
    discovery) or the endpoints; `clientId`; `scopes.read` and
    `scopes.write`; `authParams` (e.g. `access_type=offline`);
    `clientAuth` `basic` (default) or `post`. The client secret is set apart
    on the admin page. Redirect URI:
    `<bnbloc origin>/v1/component-callbacks/connections/oauth`.
  - `apiKey`: `in` `bearer`, `header` (`name`, `prefix`), `query` (`name`)
    or `basic` (`user:password`).
  - `provider`: another component speaks the protocol (`url`, `app`); see
    below. Its secret is set on the admin page.
- `policy`: read rules first (a POST search can be a read, with a `body`
  regular expression), then write rules; anything else is refused. A path
  glob has `*` (one segment) and `**` (any).
- `expiredWhen`: how the system says a sign-in ended when that is not a 401.
- `sendFrom`: where requests go out. `server` (default): from this
  component's network. `member`: from each member's computer, through their
  bridge (a system the component's network does not reach, an internal one
  the members' computers do): the component checks the policy and gives the
  bridge the member's credentials for that one request (never the agent),
  the bridge sends it and reports the answer, which is recorded and audited
  the same way; an allowed change goes through at the agent's next send of
  it. The admin page switches it per connector.
- `cliEnv`: placeholders a CLI needs before it runs (every credential sent
  to a connector host is replaced).

## Serving a request

1. The turn must be the person's own drive.
2. The host must be an enabled connector's.
3. The person must be connected; else `403` and a Connect card.
4. The policy class must be read, or a write the person allowed; else the
   change is **held** (`202` and a Review card) for a day.
5. Every credential the agent sent (`Authorization`, `Cookie`, the key's
   header) is replaced with the person's; a `401` or an `expiredWhen` match
   is retried once with fresh credentials, then answers `403` and a
   Connect-again card. `Set-Cookie` never comes back. A rate of 60 calls
   then one a second per person and system.
6. An audit row goes back with the answer (`X-Bnbloc-Audit`): method and
   path, never the query or the body.

Connected systems are reached with redirects never followed and never at
loopback, link-local (cloud metadata) or unspecified addresses; an
organization's private addresses are allowed.

## AI for the admin

The component's own AI helps the admin decide; it never sits in a
request's path and never reaches an agent
(`docs/prd/2026-10-23-connections-ai.md` in bnbloc).

- **A review of every connector**, shown beside it on the Connectors
  page: one sentence on what agents can do with it, what they read
  without asking, what they change after the member allows it, and
  findings ranked high, medium or low (a read rule that matches a
  deleting request, a host that is not the system's, a credential in the
  guide, …). It runs when a connector or an agent's draft changes and on
  "Review again"; a high finding shows on the Enable button.
- **Rules proposed from use**: requests no rule classifies and changes
  members allowed are counted per connector (method and path only). A new
  refused shape, or a change allowed three times, proposes rules (at most
  once an hour per connector; "Suggest rules" asks again). Add puts a
  rule in the policy; Dismiss drops it. A proposed rule must classify a
  request seen.

Both run through bnbloc's `assist` primitive for services, on the
organization's assist model. The prompts are content in `content/`:
publish them at platform scope once per deployment (an organization may
publish its own of the same name):

```sh
bnbloc content publish --all content --rollout auto
```

Without the `assist` capability, a model or the tasks, the page shows the
connectors without the AI part and says why.

## Provider contract

`github.com/luckylhb90/bnbloc-connections/provider`: `POST {url}/connect`,
`/authorize`, `/revoke`, JSON, signed with the connector's provider secret
(`X-Bnbloc-Signature`, bnbloc's `component.Sign` over the body). A provider
keeps what it obtains, keyed by the grant it returns at connect, and
answers `/authorize` with the headers and cookies one request carries until
a time. `pending` means the member must do something outside bnbloc
first; `admin` marks a refusal an administrator fixes.

## What is kept, where

Everything in bnbloc's sealed store (the service's values, sealed with the
platform key, gone with the uninstall, a member's with their
deprovisioning):

| Scope | Key | Value |
|---|---|---|
| `orgs/<org>` | `connector:<name>` | the connector |
| `orgs/<org>` | `secrets:<name>` | its client and provider secrets |
| `orgs/<org>` | `draft:<name>` | an agent's draft |
| `members/<subject>` | `grant:<org>:<name>` | the connection (refresh token, key or provider grant; the reach) |
| `members/<subject>` | `held:<id>` | a held change (a day) |
| `members/<subject>` | `activity:<org>` | the last 100 calls (method, path, status) |
| `shared` | `state:<random>` | an OAuth sign-in under way (15 minutes) |

Access tokens and provider authorizations are kept in memory only, until
they expire.

## Run

Environment: `BNBLOC_CONNECTIONS_BNBLOC_URL` (the gateway as this process
reaches it, required), `BNBLOC_CONNECTIONS_SECRET` (the credential the
install showed once), `BNBLOC_CONNECTIONS_LISTEN` (default `:8098`).
The bootstrap may come from AWS Secrets Manager instead: set
`BNBLOC_AWS_SECRET_ID` (and `BNBLOC_AWS_REGION` when the default chain has
none) and give the process read access to that secret (on EKS, the pod's
IAM role: `secretsmanager:GetSecretValue`). Its value is a JSON object of
environment names to values (`{"BNBLOC_CONNECTIONS_SECRET": "whsec_…"}`),
or the credential alone; a variable set in the environment wins.

Health: `GET /healthz` answers `200 {"ok":true}` (unsigned, no data): the
liveness and readiness probe. `GET /discover` is open too (the install
probe).
`BNBLOC_CONNECTIONS_NAME` is the install name (default `connections`);
`BNBLOC_CONNECTIONS_BASE_PATH` a path prefix when it is served under one.

Install: materialize `package/connections.package.json` with the base URL
the gateway reaches it at, sign it, and publish it in the Platform console
(Components) or with `bnbloc cores install`. The install answer shows the
credential once.

## Limits

- A tool that trusts only the system's roots does not trust the bridge's
  local CA (Go programs on macOS, `gh` there): its calls to a connected
  host fail their TLS check and nothing goes out unauthenticated. In the
  sandbox (Linux) and for `curl`, Python, Node and git they work.
- HTTP(S) only.
