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
  "test": {"method": "GET", "path": "/api/myself"},
  "guide": "curl https://issues.example.com/api/issue/PROJ-1"
}
```

- `hosts`: exact names; only these are intercepted.
- `connect.kind`:
  - `oauth2`: authorization code with PKCE; `issuer` (RFC 8414 / OIDC
    discovery) or the endpoints; `clientId`; `scopes.read` and
    `scopes.write`; `authParams` (e.g. `access_type=offline`);
    `clientAuth` `basic` (default) or `post`; `scopeSeparator` `" "`
    (default) or `","` for a provider that wants comma-separated scopes;
    `revocationAuth` `""` (RFC 7009) or `"bearer"` (a POST carrying the
    access token as a bearer, refreshed from the grant). The client secret is set apart
    on the admin page. Redirect URI:
    `<bnbloc origin>/v1/component-callbacks/connections/oauth`.
  - `apiKey`: `in` `bearer`, `header` (`name`, `prefix`), `query` (`name`)
    or `basic` (`user:password`). With `exchange`, the key is traded for a
    short-lived token first: a POST to `url` (one of the connector's hosts)
    of `body` (JSON, or a form with `form: true`) where `{{key}}` stands
    for the key; the token is read at `token` (a dotted path of the
    answer), kept for `expiresIn` (a dotted path to seconds) or
    `ttlSeconds` (default 1800), and carried as its own `in`, `name`,
    `prefix` say. A refused exchange (401, 403) asks to connect again. The
    component exchanges, so such a connector sends from the server. With `sign`
    (`{param, timestamp, paths}`), the member pastes the key and its secret;
    the key is carried as `in` says and each request whose path matches
    `paths`, or that already carries `param` (a client library that signed
    it with a placeholder secret), gets `timestamp` (milliseconds) when it
    has none and `param` set to the hex HMAC-SHA256, keyed by the secret, of
    its query string followed by its form body. The secret's kind decides
    the algorithm: a shared secret signs HMAC-SHA256, a PEM private key
    (pasted on one line or several) Ed25519 or RSA SHA-256. `sign.in`
    `"query"` (default: `param` at the end of the query string) or
    `"header"` (`header`, with the time in the `timestamp` header);
    `payload` is what is signed (empty: the query string then the form body;
    else a template of `{timestamp}`, `{method}`, `{path}`, `{query}`,
    `{pathQuery}`, `{body}`, `{key}` and literal text); `timestampFormat`
    `ms` (default), `s` or `iso`; `encoding` `hex` or `base64`; `paths`
    (empty: every request). `apiKey.extra` asks the member for more values
    beside the key (`{name, label, header}`: a passphrase), carried in their
    headers. The secret is never sent; sent from the member's
    computer, the bridge gets the exact signed query and body
    (`Send.RawQuery`, `ReplaceBody`).
  - `provider`: another component speaks the protocol (`url`, `app`); see
    below. Its secret is set on the admin page. `options`
    (`[{key, label, default}]`, at most 8) are on/off choices each member
    makes on their own connection (e.g. renew a token automatically): the
    Connections row shows them, and every provider call carries the
    member's values with the defaults filled in (`provider.Call.Options`).
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
  it. The admin page switches it per connector. Sent from the member's
  computer, answers stream at any size, and a request body larger than
  8 MiB (a `git push`) streams too: the component decides it on its method
  and path without seeing the body, refusing it (413) where a body rule
  could take it or the connector signs bodies; it is sent once, never
  again after a refused sign-in (renewed: run it again), and a held one,
  once allowed, lets the same method and URL through once (bnbloc's
  `docs/prd/2026-10-27-streamed-member-sends.md`). A connector that sends
  from the server refuses such a body: switch it to members' computers.
- `cliEnv`: placeholders a CLI needs before it runs (every credential sent
  to a connector host is replaced).
- `headers`: set on every request to the system whatever the agent sent
  (a mode its API takes in a header, such as `x-simulated-trading: 1`);
  never a credential, `Host` or a length.
- `test`: one read that proves a connection works (`GET` or `HEAD` of a
  path, with its query, on the first host; a read rule must take it). It
  runs right after a member or a worker connects ("It answers", or what
  the system said), and on the admin's **Try it**. For a connector that
  sends from members' computers it goes out from the person's own
  computer (bnbloc's sends from a member's computer: their action on the
  page grants one, their bnbloc desktop app sends it, the answer comes
  back as the send's report); without the desktop app running, the page
  says to open it.
- `answers`: requests answered here and never sent, `{method, path,
  status, contentType, body}` (status 200 and JSON by default): a CLI's
  own sign-in step (a token exchange) whose credential the component holds,
  answered with a placeholder the CLI then sends, which is replaced.

## Serving a request

1. The turn must be the person's own drive. A path a server may read
   otherwise than the policy (a `.` or `..` segment, also encoded, an
   encoded slash, a backslash) is refused (`400`), so the path a rule
   matched is the path the system serves.
2. The host must be an enabled connector's.
3. The person must be connected; else `403` and a Connect card.
4. An `answers` match is answered here. Otherwise the policy class must be
   read, or a write the person allowed; else the change is **held** (`202`
   and a Review card) for a day; the Connections page lists every change
   waiting, and a disconnect drops them. Allowing one on an OAuth sign-in
   that granted reading only signs in again for the write scopes. A change
   sent from the member's computer is allowed once, in its room, for an
   hour.
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

## Digital workers

Accounts of the organization that are not a person (a release bot, a wiki
bot), which agents may act as
(`docs/prd/2026-10-23-connections-digital-workers.md` in bnbloc). On the
**Digital workers** page an admin adds one: its id, name, `account` (its
name in the directory the providers sign in with), owners, the members
whose agents may act as it (`*` for everyone) and which agents (the
member's own, the organization's platform agents, a borrowed one). An
owner or an admin connects it to a system through the system's provider,
which signs in as its account (`provider.Call.Principal`, kind `worker`;
a directory that grants bot accounts directly needs no consent), and sets
its reach (each change asks the person who asked, or changes without
asking).

Who a request acts as is decided from the attested turn and the settings
people made on pages, never by the agent
(`docs/prd/2026-10-24-connections-room-identity.md` in bnbloc). In a room
(the Connections page opened from the room's header or a card in it), the
room's owner sets a worker per system for everyone, **by default** (a
member may still act as themselves there) or **required**; each member
chooses for themselves, in the room or everywhere. The first that applies:

1. the room's required worker (not connected: refused, never the person);
2. the member's choice in this room;
3. the room's default worker;
4. the member's choice everywhere;
5. the member's own connection (their own agent only);
6. a connected worker that serves them;
7. a card to connect (naming a worker its owners could connect, with
   "Choose who acts here"); a borrowed or platform agent is told only a
   digital worker serves it.

A worker applies only where its audience serves the member on that agent:
a room never widens it. Every setting goes through one writer
(`applyIdentity`), which a later proposal (an agent's, the AI's) confirmed
by the person reuses.

A person's own connection serves only their own agent. A borrowed or
platform agent gets only the systems a worker serves it at (hosts, facts).
The facts line says `jira (as Release bot)`. A change as a worker asks
the person who asked; the system sees the worker; the activity, the
worker's own record (its page) and the audit row name both. A worker's
credentials never go to a borrowed agent's computer (a connector sent
from members' computers is refused there).

## In place

A card does what it asks where it is (`component.CardCall`): a held
change's card has **Allow** and **Don't allow** (the change is made, and the
card says what the system answered) beside **Review** (the page, with
"allow without asking from now on"); a sign-in's **Connect** opens the
system's sign-in at once (OAuth) or asks the provider (SSO); only a key to
paste opens the Connections page.

## AI for the admin

Configuring starts from words: **Connect a system** on the Connectors page
takes a description, any API documentation pasted, and up to three links
to the documentation (the platform fetches them for the task), and the AI
drafts the connector, which arrives as a draft with its review; the JSON
stays the manual path. A review's finding comes with its **fix** (a JSON
merge patch, never enabling, renaming or moving where requests go out),
applied with one click and reviewed again.

The AI checks its work (`docs/prd/2026-10-25-ai-checks-its-work.md` in
bnbloc): a draft that does not parse strictly or validate, and a fix that
would not make a valid connector, go back to the model with the error,
up to three rounds (`component.ServiceClient.AssistChecked`); a draft
still wrong after that says why. **Try it** sends the connector's `test`
with the admin's own connection; a failure (status and the body's first
characters, every credential value removed) is kept and the review runs
again with it, so its fix answers what the system said.

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

A `pending` connect means the member does something outside bnbloc: open
the page the answer names in `open` (an https consent page, opened in place
like a sign-in; or an app link), or answer a chat card. A connector whose
consent page works only in one browser (a chat app's own) names it in
`provider.openIn` (a regular expression of its user agent): there Connect
opens the page in place; anywhere else it connects with `notify`, asking the
provider for its own prompt (a chat card) instead. The member's Connections
page then waits, followed by a hidden frame of the page that reloads itself
every 5 seconds and tells the page when what it waits for changed (a
sandboxed page cannot fetch itself); the page reloads only then, never while
the person types, for up to 15 minutes. Each look asks the provider with
`check` (report only, never prompt) and connects once it answers
`connected`, as does the member's agent's next request to that system, so
nobody presses Connect twice.

## What is kept, where

Everything in bnbloc's sealed store (the service's values, sealed with the
platform key, gone with the uninstall, a member's with their
deprovisioning):

| Scope | Key | Value |
|---|---|---|
| `orgs/<org>` | `connector:<name>` | the connector |
| `orgs/<org>` | `secrets:<name>` | its client and provider secrets |
| `orgs/<org>` | `draft:<name>` | an agent's draft |
| `orgs/<org>` | `try:<name>` | the admin's last Try it (status, one line, no credential) |
| `orgs/<org>` | `send:<id>` | a try a computer is sending (minutes) |
| `members/<subject>` | `check:<org>:<name>` | the member's last check after connecting |
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
Run **one replica**: one grant's credentials are made one at a time in
the process (a refresh token is never spent twice), and the activity, the
rate and the signals are kept by that process; replicas would race them.

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
