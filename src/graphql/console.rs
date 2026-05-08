use axum::response::Html;

pub async fn graphql_console() -> Html<&'static str> {
    Html(console_html())
}

pub(crate) fn console_html() -> &'static str {
    r###"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Atom GraphQL Console</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3f5f7;
      --panel: #ffffff;
      --soft: #f8fafc;
      --tint: #eef7f6;
      --border: #d7dee7;
      --border-strong: #b7c3d0;
      --text: #17202a;
      --muted: #607083;
      --accent: #0f766e;
      --accent-dark: #115e59;
      --accent-soft: #dff5f2;
      --warn: #936800;
      --danger: #b42318;
      --code: #101828;
      --shadow: 0 1px 2px rgba(16, 24, 40, .06);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    button, input, select, textarea {
      font: inherit;
    }

    button {
      min-height: 36px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      padding: 8px 10px;
      cursor: pointer;
    }

    button:hover { border-color: var(--border-strong); }

    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
      font-weight: 650;
    }

    button.primary:hover {
      background: var(--accent-dark);
      border-color: var(--accent-dark);
    }

    button.linkish {
      border-color: transparent;
      background: transparent;
      color: var(--accent-dark);
      padding-left: 0;
    }

    input, select, textarea {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 8px 9px;
    }

    textarea {
      min-height: 132px;
      resize: vertical;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 13px;
      line-height: 1.45;
      tab-size: 2;
    }

    label {
      display: grid;
      gap: 5px;
      color: var(--muted);
      font-size: 12px;
    }

    h1, h2, h3, p { margin-top: 0; }

    h1 {
      font-size: 26px;
      line-height: 1.2;
      margin-bottom: 7px;
      letter-spacing: 0;
    }

    h2 {
      font-size: 17px;
      line-height: 1.3;
      margin-bottom: 10px;
      letter-spacing: 0;
    }

    h3 {
      font-size: 13px;
      line-height: 1.3;
      margin: 16px 0 8px;
      letter-spacing: 0;
      text-transform: uppercase;
      color: var(--muted);
    }

    p { line-height: 1.5; }

    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      background: var(--soft);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1px 4px;
    }

    pre {
      margin: 0;
      min-height: 112px;
      max-height: 360px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      background: var(--soft);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--code);
      padding: 10px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 13px;
      line-height: 1.45;
    }

    details {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--soft);
      padding: 8px 10px;
      margin-top: 10px;
    }

    summary {
      cursor: pointer;
      color: var(--accent-dark);
      font-weight: 650;
      font-size: 13px;
    }

    details pre, details textarea { margin-top: 8px; }

    .app-shell {
      display: grid;
      grid-template-columns: 292px minmax(0, 1fr) 292px;
      min-height: 100vh;
    }

    .side-nav {
      background: var(--panel);
      border-right: 1px solid var(--border);
      min-width: 0;
    }

    .docs-panel {
      background: var(--panel);
      border-left: 1px solid var(--border);
      min-width: 0;
    }

    .side-scroll, .docs-scroll {
      height: 100vh;
      overflow: auto;
    }

    .brand {
      padding: 18px;
      border-bottom: 1px solid var(--border);
    }

    .brand h1 {
      font-size: 19px;
      margin-bottom: 4px;
    }

    .subtitle, .help, .muted {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
    }

    .nav-section {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }

    .nav-list {
      display: grid;
      gap: 6px;
    }

    .nav-button {
      width: 100%;
      display: grid;
      gap: 2px;
      text-align: left;
      border-color: transparent;
      background: transparent;
      padding: 9px 10px;
    }

    .nav-button.active {
      background: var(--accent-soft);
      border-color: #a9ded8;
      color: var(--accent-dark);
    }

    .nav-button strong { font-size: 13px; }

    .nav-button span {
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .main {
      height: 100vh;
      min-width: 0;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr);
    }

    .topbar {
      background: var(--panel);
      border-bottom: 1px solid var(--border);
      padding: 12px;
      display: grid;
      grid-template-columns: minmax(150px, 240px) minmax(240px, 1fr) auto auto;
      gap: 9px;
      align-items: end;
    }

    .workspace {
      height: 100%;
      min-width: 0;
      overflow: auto;
      padding: 16px;
    }

    .screen {
      display: none;
      max-width: 1160px;
      margin: 0 auto;
    }

    .screen.active { display: block; }

    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 15px;
      margin-bottom: 14px;
    }

    .panel.tint { background: var(--tint); }

    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .grid-3 {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .split {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 14px;
    }

    .task-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .task-card {
      display: grid;
      gap: 6px;
      min-height: 118px;
      text-align: left;
      padding: 14px;
      align-content: start;
    }

    .task-card strong { font-size: 15px; }

    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 10px;
    }

    .status-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      max-width: 100%;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--soft);
      color: var(--muted);
      padding: 3px 8px;
      font-size: 12px;
      line-height: 1.25;
    }

    .badge.ok {
      background: var(--accent-soft);
      border-color: #b9e4df;
      color: var(--accent-dark);
    }

    .badge.warn {
      background: #fff7df;
      border-color: #ead49a;
      color: var(--warn);
    }

    .badge.error {
      background: #fff0ed;
      border-color: #f0b8ae;
      color: var(--danger);
    }

    .notice {
      border: 1px solid #e9d7a6;
      background: #fff9e9;
      color: #6b4d00;
      border-radius: 8px;
      padding: 10px;
      font-size: 13px;
      line-height: 1.45;
      margin-top: 10px;
    }

    .notice.danger {
      border-color: #f0b8ae;
      background: #fff0ed;
      color: var(--danger);
    }

    .wizard-nav {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
      margin-bottom: 12px;
    }

    .wizard-tab {
      text-align: left;
      min-height: 68px;
      padding: 10px;
    }

    .wizard-tab.active {
      background: var(--accent-soft);
      border-color: #a9ded8;
    }

    .wizard-step { display: none; }
    .wizard-step.active { display: block; }

    .builder-sections {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }

    .mini-panel {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      background: var(--soft);
    }

    .operation-list {
      display: grid;
      gap: 7px;
      max-height: 260px;
      overflow: auto;
      padding-right: 2px;
    }

    .operation-button {
      display: grid;
      gap: 4px;
      text-align: left;
      padding: 9px;
    }

    .operation-button strong { font-size: 13px; }

    .operation-button span {
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .schema-docs {
      display: grid;
      gap: 10px;
      font-size: 13px;
      line-height: 1.45;
    }

    .schema-docs dt {
      font-weight: 700;
      color: var(--text);
    }

    .schema-docs dd {
      margin: 2px 0 8px;
      color: var(--muted);
    }

    .type-list {
      max-height: 220px;
      overflow: auto;
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      color: var(--muted);
      background: var(--soft);
      margin: 1px;
    }

    .field-list {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 6px 10px;
      max-height: 180px;
      overflow: auto;
      padding: 9px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--soft);
      margin-top: 10px;
    }

    .field-list label {
      display: flex;
      gap: 6px;
      align-items: center;
      color: var(--text);
      font-size: 13px;
    }

    .recipe-preview {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 12px;
    }

    .summary-box {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--soft);
      padding: 10px;
      min-height: 46px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
      margin-top: 10px;
    }

    .hidden { display: none; }

    @media (max-width: 1040px) {
      .app-shell { grid-template-columns: 260px minmax(0, 1fr); }
      .docs-panel { display: none; }
      .task-grid, .builder-sections, .wizard-nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .topbar { grid-template-columns: minmax(160px, 1fr) minmax(160px, 1fr); }
    }

    @media (max-width: 760px) {
      .app-shell { display: block; }
      .side-scroll, .docs-scroll, .main { height: auto; }
      .side-nav { border-right: 0; border-bottom: 1px solid var(--border); }
      .workspace { height: auto; }
      .grid, .grid-3, .split, .task-grid, .builder-sections, .wizard-nav, .recipe-preview { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <aside class="side-nav">
      <div class="side-scroll">
        <div class="brand">
          <h1>Atom GraphQL Console</h1>
          <div class="subtitle">Hasura-like developer console and API Builder for generic Atom GraphQL.</div>
        </div>

        <section class="nav-section">
          <h2>Start</h2>
          <div class="nav-list">
            <button class="nav-button active" data-screen="start"><strong>What do you want to do?</strong><span>Pick a task</span></button>
            <button class="nav-button" data-screen="guided"><strong>Guided setup</strong><span>Tenant to authz check</span></button>
            <button class="nav-button" data-screen="api-builder"><strong>API Builder</strong><span>Reusable recipes</span></button>
            <button class="nav-button" data-screen="login"><strong>login helper</strong><span>Get a token</span></button>
          </div>
        </section>

        <section class="nav-section">
          <h2>Build</h2>
          <div class="nav-list">
            <button class="nav-button" data-screen="tenant"><strong>Tenant builder</strong><span>Create an isolation boundary</span></button>
            <button class="nav-button" data-screen="profile"><strong>Profile builder</strong><span>Define subtype and schema</span></button>
            <button class="nav-button" data-screen="entity"><strong>Entity builder</strong><span>People, devices, services</span></button>
            <button class="nav-button" data-screen="resource"><strong>Resource builder</strong><span>Protected objects</span></button>
            <button class="nav-button" data-screen="policy"><strong>Policy builder</strong><span>Allow access</span></button>
            <button class="nav-button" data-screen="authz"><strong>Authz builder</strong><span>Test access</span></button>
            <button class="nav-button" data-screen="credentials"><strong>Credential builder</strong><span>Passwords and API keys</span></button>
          </div>
        </section>

        <section class="nav-section">
          <h2>Advanced</h2>
          <div class="nav-list">
            <button class="nav-button" data-screen="advanced"><strong>Advanced GraphQL</strong><span>operation explorer</span></button>
            <button class="nav-button" data-screen="assistant"><strong>AI Assistant placeholder</strong><span>Copyable prompt only</span></button>
          </div>
        </section>

        <section class="nav-section">
          <h2>Model Rules</h2>
          <p class="help">Atom GraphQL is generic. Tenant, entity, resource, policy, profile, and credential operations are the source of truth.</p>
          <p class="help"><strong>kind</strong> is Atom internal runtime/authz kind. <strong>profile</strong> is the user or domain subtype. <strong>profileVersion</strong> is validation and history only.</p>
        </section>
      </div>
    </aside>

    <main class="main">
      <div class="topbar">
        <label>Endpoint
          <input id="endpoint" value="/graphql" autocomplete="off" />
        </label>
        <label>Authorization Bearer token
          <input id="token" type="password" autocomplete="off" placeholder="Use login helper or paste token" />
        </label>
        <button id="clearToken">Clear token</button>
        <button id="refreshSchema">Refresh schema</button>
        <div id="connectionStatus" class="status-row" style="grid-column: 1 / -1;">
          <span class="badge warn">Schema not loaded</span>
          <span class="badge warn">Not authenticated</span>
        </div>
        <div id="endpointWarning" class="notice danger hidden" style="grid-column: 1 / -1;"></div>
      </div>

      <div class="workspace">
        <section id="screen-start" class="screen active">
          <div class="panel tint">
            <h1>What do you want to do?</h1>
            <p class="help">Use plain mode by default. Each task generates generic Atom GraphQL, shows variables, and keeps the advanced query view collapsed until you need it.</p>
            <p class="help">Includes login helper, operation explorer, entity builder, resource builder, policy builder, authz builder, and AI Assistant placeholder.</p>
          </div>
          <div class="task-grid">
            <button class="task-card" data-screen="guided"><strong>Set up a tenant</strong><span class="help">Create a tenant, entity, resource, policy, and access test in one guided flow.</span></button>
            <button class="task-card" data-screen="entity"><strong>Add a person, device, or service</strong><span class="help">Create an entity from an entity profile and schema-backed attributes.</span></button>
            <button class="task-card" data-screen="resource"><strong>Create a protected object</strong><span class="help">Create a generic resource such as a channel, file, report, or workflow.</span></button>
            <button class="task-card" data-screen="policy"><strong>Allow access</strong><span class="help">Build an allow or deny policy with subject, grant, scope, and conditions.</span></button>
            <button class="task-card" data-screen="authz"><strong>Test access</strong><span class="help">Run an authorization check or privileged/admin explanation.</span></button>
            <button class="task-card" data-screen="credentials"><strong>Manage credentials</strong><span class="help">List credentials, create API keys, set passwords, and revoke credentials.</span></button>
            <button class="task-card" data-screen="advanced"><strong>Explore GraphQL directly</strong><span class="help">Use the GraphQL Operation Explorer in Advanced GraphQL.</span></button>
            <button class="task-card" data-screen="api-builder"><strong>Use API Builder recipes</strong><span class="help">Generate GraphQL, curl, and JavaScript snippets from reusable recipes.</span></button>
          </div>
        </section>

        <section id="screen-login" class="screen">
          <div class="panel">
            <h1>login helper</h1>
            <p class="help">Login is public. Tokens can be stored in localStorage for this browser, and Authorization is sent only to same-origin <code>/graphql</code>.</p>
            <div class="grid-3">
              <label>Identifier<input id="loginIdentifier" value="atom-admin" autocomplete="username" /></label>
              <label>Secret<input id="loginSecret" type="password" value="change-me" autocomplete="current-password" /></label>
              <label>Credential kind<input id="loginKind" value="password" /></label>
            </div>
            <div class="actions">
              <button class="primary" id="runLogin">Run login</button>
              <button id="copyLoginMutation">Copy GraphQL</button>
            </div>
            <div id="loginSummary" class="summary-box">No login request yet.</div>
            <details>
              <summary>Advanced GraphQL preview</summary>
              <pre id="loginGraphql"></pre>
            </details>
            <details>
              <summary>Variables</summary>
              <pre id="loginVariables"></pre>
            </details>
            <details>
              <summary>Raw result</summary>
              <pre id="loginResult"></pre>
            </details>
          </div>
        </section>

        <section id="screen-guided" class="screen">
          <div class="panel tint">
            <h1>Guided setup wizard</h1>
            <p class="help">Create a tenant, add an entity, create a resource, grant access, and test the decision. Each step shows a result summary and suggests the next action.</p>
          </div>
          <div class="wizard-nav">
            <button class="wizard-tab active" data-step="1"><strong>Step 1</strong><br><span class="help">Create tenant</span></button>
            <button class="wizard-tab" data-step="2"><strong>Step 2</strong><br><span class="help">Add entity</span></button>
            <button class="wizard-tab" data-step="3"><strong>Step 3</strong><br><span class="help">Create resource</span></button>
            <button class="wizard-tab" data-step="4"><strong>Step 4</strong><br><span class="help">Grant access</span></button>
            <button class="wizard-tab" data-step="5"><strong>Step 5</strong><br><span class="help">Test access</span></button>
          </div>

          <div id="wizard-step-1" class="panel wizard-step active">
            <h2>Step 1: Create tenant</h2>
            <p class="help">A tenant is an isolation boundary for related identities and protected objects.</p>
            <div class="grid">
              <label>Tenant name<input id="setupTenantName" value="factory-a" /></label>
              <label>Tenant route<input id="setupTenantRoute" value="factory-a" /></label>
            </div>
            <label>Attributes JSON<textarea id="setupTenantAttributes" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewSetupTenant">Preview</button>
              <button class="primary" id="runSetupTenant">Run createTenant</button>
            </div>
            <div id="setupTenantSummary" class="summary-box">Next: create the tenant, then add an entity inside it.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="setupTenantGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="setupTenantVariables"></pre></details>
            <div class="actions"><button data-step="2" class="next-step">Next: Add entity</button></div>
          </div>

          <div id="wizard-step-2" class="panel wizard-step">
            <h2>Step 2: Add entity</h2>
            <p class="help">An entity is a principal: a person, device, service, workload, or application.</p>
            <div class="grid">
              <label>Tenant ID<input id="setupEntityTenantId" placeholder="created tenant id" /></label>
              <label>Internal kind<select id="setupEntityKind"><option>human</option><option selected>device</option><option>service</option><option>workload</option><option>application</option></select></label>
              <label>Profile<select id="setupEntityProfile"></select></label>
              <label>Profile version<select id="setupEntityProfileVersion"></select></label>
              <label>Name<input id="setupEntityName" value="device-001" /></label>
            </div>
            <div class="actions">
              <button id="loadSetupProfiles">Load profiles</button>
              <span id="setupEntityBadges" class="status-row"></span>
            </div>
            <label>Attributes JSON<textarea id="setupEntityAttributes" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewSetupEntity">Preview</button>
              <button class="primary" id="runSetupEntity">Run createEntity</button>
            </div>
            <div id="setupEntitySummary" class="summary-box">Next: add an entity from a profile or internal kind, then create a protected resource.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="setupEntityGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="setupEntityVariables"></pre></details>
            <div class="actions"><button data-step="3" class="next-step">Next: Create resource</button></div>
          </div>

          <div id="wizard-step-3" class="panel wizard-step">
            <h2>Step 3: Create resource</h2>
            <p class="help">Resources are things protected by Atom policies.</p>
            <div class="grid">
              <label>Tenant ID<input id="setupResourceTenantId" placeholder="created tenant id" /></label>
              <label>Resource kind<input id="setupResourceKind" value="channel" /></label>
              <label>Name<input id="setupResourceName" value="telemetry" /></label>
            </div>
            <label>Attributes JSON<textarea id="setupResourceAttributes" spellcheck="false">{"topic":"telemetry"}</textarea></label>
            <div class="actions">
              <button id="previewSetupResource">Preview</button>
              <button class="primary" id="runSetupResource">Run createResource</button>
            </div>
            <div id="setupResourceSummary" class="summary-box">Next: create the protected object, then grant an entity access to it.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="setupResourceGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="setupResourceVariables"></pre></details>
            <div class="actions"><button data-step="4" class="next-step">Next: Grant access</button></div>
          </div>

          <div id="wizard-step-4" class="panel wizard-step">
            <h2>Step 4: Grant access</h2>
            <p class="help">An allow policy connects who can do what on which scope. Deny policies override allow policies.</p>
            <div class="grid">
              <label>Tenant ID<input id="setupPolicyTenantId" placeholder="created tenant id" /></label>
              <label>Subject ID<input id="setupPolicySubjectId" placeholder="created entity id" /></label>
              <label>Capability ID<input id="setupPolicyGrantId" placeholder="capability uuid" /></label>
              <label>Resource ID<input id="setupPolicyResourceId" placeholder="created resource id" /></label>
              <label>Effect<select id="setupPolicyEffect"><option selected>allow</option><option>deny</option></select></label>
            </div>
            <label>Conditions JSON<textarea id="setupPolicyConditions" spellcheck="false">{}</textarea></label>
            <div id="setupPolicyHumanSummary" class="summary-box">Allow subject to capability on resource.</div>
            <div class="actions">
              <button id="previewSetupPolicy">Preview</button>
              <button class="primary" id="runSetupPolicy">Run createPolicy</button>
            </div>
            <div id="setupPolicySummary" class="summary-box">Next: run an authorization check with the subject, action, and resource.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="setupPolicyGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="setupPolicyVariables"></pre></details>
            <div class="actions"><button data-step="5" class="next-step">Next: Test access</button></div>
          </div>

          <div id="wizard-step-5" class="panel wizard-step">
            <h2>Step 5: Test access</h2>
            <p class="help">Use the same subject, action, and resource that your application would ask Atom to authorize.</p>
            <div class="grid">
              <label>Subject ID<input id="setupAuthzSubjectId" placeholder="created entity id" /></label>
              <label>Action<input id="setupAuthzAction" value="publish" /></label>
              <label>Resource ID<input id="setupAuthzResourceId" placeholder="created resource id" /></label>
            </div>
            <label>Context JSON<textarea id="setupAuthzContext" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewSetupAuthz">Preview</button>
              <button class="primary" id="runSetupAuthz">Run authzCheck</button>
            </div>
            <div id="setupAuthzSummary" class="summary-box">Run the check to see Allowed or Denied with a reason.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="setupAuthzGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="setupAuthzVariables"></pre></details>
          </div>
        </section>

        <section id="screen-tenant" class="screen">
          <div class="panel">
            <h1>Tenant builder</h1>
            <p class="help">Create an isolation boundary. Domain-like applications call <code>createTenant</code>.</p>
            <div class="grid">
              <label>Name<input id="tenantName" value="factory-a" /></label>
              <label>Route<input id="tenantRoute" value="factory-a" /></label>
            </div>
            <label>Tags, comma separated<input id="tenantTags" placeholder="iot, production" /></label>
            <label>Attributes JSON<textarea id="tenantAttributes" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewTenant">Preview</button>
              <button class="primary" id="runTenant">Run createTenant</button>
            </div>
            <div id="tenantSummary" class="summary-box">What happened? No tenant request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="tenantGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="tenantVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="tenantResult"></pre></details>
          </div>
        </section>

        <section id="screen-profile" class="screen">
          <div class="panel">
            <h1>Profile builder</h1>
            <p class="help">A profile is a user/domain subtype and schema. It is separate from Atom internal kind.</p>
            <div class="grid">
              <label>Tenant<select id="profileTenantSelect"></select></label>
              <label>Or tenant ID<input id="profileTenantId" placeholder="optional tenant uuid" /></label>
              <label>Object kind<input id="profileObjectKind" value="entity" /></label>
              <label>Internal kind<select id="profileKind"><option>human</option><option selected>device</option><option>service</option><option>workload</option><option>application</option></select></label>
              <label>Profile key<input id="profileKey" value="client" /></label>
              <label>Display name<input id="profileDisplayName" value="Client" /></label>
              <label>Status<input id="profileStatus" value="active" /></label>
              <label>Description<input id="profileDescription" placeholder="optional description" /></label>
            </div>
            <div class="actions">
              <button id="loadTenantsForProfile">Load tenants</button>
              <button id="previewProfile">Preview createProfile</button>
              <button class="primary" id="runProfile">Run createProfile</button>
            </div>
            <h3>Profile version</h3>
            <p class="help">Profile versions hold JSON Schema for validation and history only.</p>
            <div class="grid">
              <label>Profile ID<input id="profileVersionProfileId" placeholder="profile uuid" /></label>
              <label>Version<input id="profileVersionNumber" type="number" value="1" /></label>
              <label>Status<input id="profileVersionStatus" value="active" /></label>
            </div>
            <label>JSON Schema<textarea id="profileJsonSchema" spellcheck="false">{"type":"object","properties":{"serial_no":{"type":"string"}}}</textarea></label>
            <label>UI Schema<textarea id="profileUiSchema" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewProfileVersion">Preview createProfileVersion</button>
              <button class="primary" id="runProfileVersion">Run createProfileVersion</button>
              <button id="refreshProfilesAfterProfile">Refresh entity profiles</button>
            </div>
            <div id="profileSummary" class="summary-box">What happened? No profile request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="profileGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="profileVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="profileResult"></pre></details>
          </div>
        </section>

        <section id="screen-entity" class="screen">
          <div class="panel">
            <h1>Entity builder</h1>
            <p class="help">Create people, devices, services, workloads, or applications. Select a profile first; Atom derives internal kind from the selected profile.</p>
            <div class="grid">
              <label>Tenant<select id="entityTenantSelect"></select></label>
              <label>Or tenant ID<input id="entityTenantId" placeholder="optional tenant uuid" /></label>
              <label>Internal kind<select id="entityKind"><option>human</option><option selected>device</option><option>service</option><option>workload</option><option>application</option></select></label>
              <label>Profile<select id="entityProfile"></select></label>
              <label>Profile version<select id="entityProfileVersion"></select></label>
              <label>Name<input id="entityName" placeholder="entity-001" /></label>
            </div>
            <div class="actions">
              <button id="loadTenantsForEntity">Load tenants</button>
              <button id="loadProfiles">Load profiles</button>
              <span id="entityBadges" class="status-row"></span>
            </div>
            <h3>Attributes from profile JSON Schema</h3>
            <div id="schemaForm" class="grid"></div>
            <label>Attributes JSON fallback<textarea id="entityAttributes" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button id="previewEntity">Preview</button>
              <button class="primary" id="runEntity">Run createEntity</button>
            </div>
            <div id="entitySummary" class="summary-box">What happened? No entity request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="entityGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="entityVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="entityResult"></pre></details>
          </div>
        </section>

        <section id="screen-resource" class="screen">
          <div class="panel">
            <h1>Resource builder</h1>
            <p class="help">Resources are things protected by Atom policies.</p>
            <p class="help">A channel is just <code>createResource(kind: "channel")</code>.</p>
            <div class="grid">
              <label>Tenant<select id="resourceTenantSelect"></select></label>
              <label>Or tenant ID<input id="resourceTenantId" placeholder="optional tenant uuid" /></label>
              <label>Resource kind<select id="resourceKindPreset"><option selected>channel</option><option>file</option><option>report</option><option>workflow</option><option>custom</option></select></label>
              <label>Custom kind<input id="resourceKindCustom" placeholder="custom kind" /></label>
              <label>Name<input id="resourceName" value="telemetry" /></label>
              <label>Owner ID<input id="resourceOwnerId" placeholder="optional entity uuid" /></label>
            </div>
            <label>Attributes JSON<textarea id="resourceAttributes" spellcheck="false">{"topic":"telemetry"}</textarea></label>
            <div class="actions">
              <button id="loadTenantsForResource">Load tenants</button>
              <button id="previewResource">Preview</button>
              <button class="primary" id="runResource">Run createResource</button>
            </div>
            <div id="resourceSummary" class="summary-box">What happened? No resource request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="resourceGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="resourceVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="resourceResult"></pre></details>
          </div>
        </section>

        <section id="screen-policy" class="screen">
          <div class="panel">
            <h1>Policy builder</h1>
            <p class="help">Build a visual policy from who, can do, on, and when. Connection-like applications call <code>createPolicy</code>.</p>
            <div class="builder-sections">
              <div class="mini-panel">
                <h2>WHO</h2>
                <label>Subject kind<select id="policySubjectKind"><option selected>entity</option><option>group</option></select></label>
                <label>Subject selector<select id="policySubjectSelect"></select></label>
                <label>Or manual subject ID<input id="policySubjectId" /></label>
                <div class="actions"><button id="loadPolicySubjects">Load subjects</button></div>
              </div>
              <div class="mini-panel">
                <h2>CAN DO</h2>
                <label>Grant kind<select id="policyGrantKind"><option selected>capability</option><option>role</option></select></label>
                <label>Capability or role<select id="policyGrantSelect"></select></label>
                <label>Or manual grant ID<input id="policyGrantId" /></label>
                <div class="actions"><button id="loadPolicyGrants">Load grants</button></div>
              </div>
              <div class="mini-panel">
                <h2>ON</h2>
                <label>Scope kind<select id="policyScopeKind"><option>platform</option><option>tenant</option><option>object_kind</option><option>object_type</option><option selected>object</option></select></label>
                <label>Tenant<select id="policyTenantSelect"></select></label>
                <label>Object selector<select id="policyObjectSelect"></select></label>
                <label>Scope ref<input id="policyScopeRef" placeholder="resource uuid, tenant uuid, or kind" /></label>
                <div class="actions"><button id="loadPolicyObjects">Load objects</button></div>
              </div>
              <div class="mini-panel">
                <h2>WHEN</h2>
                <label>Effect<select id="policyEffect"><option selected>allow</option><option>deny</option></select></label>
                <label>Conditions JSON<textarea id="policyConditions" spellcheck="false">{}</textarea></label>
              </div>
            </div>
            <div id="policyHumanSummary" class="summary-box">Allow subject to capability on scope.</div>
            <div class="actions">
              <button id="loadTenantsForPolicy">Load tenants</button>
              <button id="previewPolicy">Preview</button>
              <button class="primary" id="runPolicy">Run createPolicy</button>
              <button id="testThisPolicy">Test this policy</button>
            </div>
            <div id="policySummary" class="summary-box">What happened? No policy request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="policyGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="policyVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="policyResult"></pre></details>
          </div>
        </section>

        <section id="screen-authz" class="screen">
          <div class="panel">
            <h1>Authz builder</h1>
            <p class="help">Run an authorization decision against Atom's online PDP. Use authzCheck for normal application paths.</p>
            <div class="grid">
              <label>Subject ID<input id="authzSubjectId" /></label>
              <label>Action<input id="authzAction" value="publish" /></label>
              <label>Resource ID<input id="authzResourceId" /></label>
              <label>Object kind<input id="authzObjectKind" placeholder="optional object kind" /></label>
              <label>Object ID<input id="authzObjectId" placeholder="optional object uuid" /></label>
            </div>
            <label>Context JSON<textarea id="authzContext" spellcheck="false">{}</textarea></label>
            <div class="actions">
              <button class="primary" id="runAuthzCheck">Run authzCheck</button>
              <button id="runAuthzExplain">Run authzExplain (privileged/admin)</button>
              <button id="previewAuthz">Preview</button>
            </div>
            <div id="authzNarrative" class="summary-box">Run a check to see an Allowed or Denied badge, reason, details, and next suggested action.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="authzGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="authzVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="authzResult"></pre></details>
          </div>
        </section>

        <section id="screen-credentials" class="screen">
          <div class="panel">
            <h1>Credential builder</h1>
            <p class="help">Manage credentials for an entity. API key plaintext is revealed once by Atom and cannot be recovered later.</p>
            <div class="grid">
              <label>Entity ID<input id="credentialEntityId" /></label>
              <label>Credential ID for revoke<input id="credentialId" /></label>
              <label>API key description<input id="apiKeyDescription" placeholder="automation key" /></label>
              <label>API key expires at<input id="apiKeyExpiresAt" placeholder="optional RFC3339 timestamp" /></label>
              <label>Password<input id="passwordSecret" type="password" placeholder="new password" /></label>
            </div>
            <div class="actions">
              <button id="listCredentials">List credentials</button>
              <button class="primary" id="createApiKey">Create API key</button>
              <button id="createPassword">Create password</button>
              <button id="revokeCredential">Revoke credential</button>
            </div>
            <div id="credentialSummary" class="summary-box">What happened? No credential request yet.</div>
            <details><summary>Advanced GraphQL preview</summary><pre id="credentialGraphql"></pre></details>
            <details><summary>Variables</summary><pre id="credentialVariables"></pre></details>
            <details><summary>Raw result</summary><pre id="credentialResult"></pre></details>
          </div>
        </section>

        <section id="screen-api-builder" class="screen">
          <div class="panel tint">
            <h1>API Builder</h1>
            <p class="help">Pick a recipe, fill a plain-language form, then generate GraphQL, variables, curl, and JavaScript fetch snippets. Saved recipes are stored in localStorage.</p>
          </div>
          <div class="panel">
            <div class="grid">
              <label>Recipe<select id="recipeSelect"></select></label>
              <label>Saved recipes/examples<select id="savedRecipes"></select></label>
            </div>
            <div id="recipeForm" class="grid" style="margin-top: 10px;"></div>
            <div class="actions">
              <button id="generateRecipe">Generate</button>
              <button class="primary" id="runRecipe">Run it</button>
              <button id="copyRecipeGraphql">Copy GraphQL</button>
              <button id="copyRecipeCurl">Copy curl</button>
              <button id="copyRecipeJs">Copy JavaScript fetch snippet</button>
              <button id="saveRecipe">Save recipe</button>
              <button id="loadRecipe">Load saved</button>
            </div>
            <div id="recipeSummary" class="summary-box">Choose a recipe to start.</div>
            <div class="recipe-preview">
              <div>
                <h2>Generated GraphQL</h2>
                <pre id="recipeGraphql"></pre>
              </div>
              <div>
                <h2>Variables JSON</h2>
                <pre id="recipeVariables"></pre>
              </div>
            </div>
            <details><summary>curl</summary><pre id="recipeCurl"></pre></details>
            <details><summary>JavaScript fetch</summary><pre id="recipeJs"></pre></details>
            <details><summary>Raw result</summary><pre id="recipeResult"></pre></details>
          </div>
        </section>

        <section id="screen-advanced" class="screen">
          <div class="panel">
            <h1>Advanced GraphQL</h1>
            <p class="help">GraphQL operation explorer for direct schema inspection and execution. This advanced section uses introspection only.</p>
            <div class="grid">
              <label>Search operations and types<input id="schemaSearch" placeholder="filter operations and types" autocomplete="off" /></label>
              <label>Saved examples<select id="savedExamples"></select></label>
            </div>
            <div class="actions">
              <button id="loadExample">Load example</button>
              <button id="saveExample">Save current example</button>
            </div>
            <div id="schemaStatus" class="status-row" style="margin-top: 10px;">
              <span class="badge warn">Loading schema</span>
            </div>
          </div>
          <div class="split">
            <div class="panel">
              <h2>Queries</h2>
              <div id="queryOps" class="operation-list"></div>
              <h2 style="margin-top: 16px;">Mutations</h2>
              <div id="mutationOps" class="operation-list"></div>
            </div>
            <div class="panel">
              <h2>Selected operation</h2>
              <div id="selectedOperation" class="help">Select a query or mutation. Required arguments appear in the generated variables skeleton.</div>
              <div id="returnFields" class="field-list hidden"></div>
              <div class="actions">
                <button id="copyQuery">Copy query</button>
                <button class="primary" id="runOperation">Run operation</button>
              </div>
            </div>
          </div>
          <div class="split">
            <div class="panel">
              <h2>GraphQL</h2>
              <textarea id="queryEditor" spellcheck="false"></textarea>
            </div>
            <div class="panel">
              <h2>Variables JSON</h2>
              <textarea id="variablesEditor" spellcheck="false">{}</textarea>
            </div>
          </div>
          <div class="panel">
            <div class="response-header status-row">
              <h2 style="margin-bottom: 0;">Response viewer</h2>
              <span id="responseStatus" class="badge">No request yet</span>
            </div>
            <div id="responseSummary" class="summary-box">What happened? No advanced request yet.</div>
            <pre id="responseViewer"></pre>
          </div>
        </section>

        <section id="screen-assistant" class="screen">
          <div class="panel">
            <h1>AI Assistant placeholder</h1>
            <div class="notice">No external LLM calls are made. Review generated GraphQL before running.</div>
            <p class="help">LLM execution is not wired yet. Copy this prompt into your AI tool.</p>
            <p class="help">Describe a request. The console will build a copyable prompt with the current schema summary, available operations, selected context, Atom model rules, and your request.</p>
            <label>Natural-language request<textarea id="assistantRequest" spellcheck="false" placeholder="Example: create a device from the client profile and let it publish to a channel resource"></textarea></label>
            <div class="actions">
              <button id="generatePrompt">Generate prompt</button>
              <button id="copyPrompt">Copy prompt</button>
            </div>
            <h2>Copyable prompt</h2>
            <pre id="assistantPrompt"></pre>
            <h2>Expected response format</h2>
            <pre id="assistantExpected">GraphQL operation:
<query or mutation>

Variables JSON:
{}

Explanation:
<plain-language explanation and assumptions></pre>
          </div>
        </section>
      </div>
    </main>

    <aside class="docs-panel">
      <div class="docs-scroll">
        <div class="brand">
          <h1>Schema Docs</h1>
          <div class="subtitle">Core Atom model reference from GraphQL introspection.</div>
        </div>
        <section class="nav-section">
          <dl class="schema-docs">
            <dt>Tenant</dt><dd>Isolation boundary.</dd>
            <dt>Entity</dt><dd>Principal; human/device/service/workload/application.</dd>
            <dt>Resource</dt><dd>Protected object, for example channel/rule/report.</dd>
            <dt>Group</dt><dd>Collection of entities.</dd>
            <dt>Profile</dt><dd>User/domain subtype/schema.</dd>
            <dt>ProfileVersion</dt><dd>JSON Schema validation/history.</dd>
            <dt>Policy</dt><dd>Grants capability/role over scope.</dd>
          </dl>
        </section>
        <section class="nav-section">
          <h2>External Mapping</h2>
          <p class="help">Magistrala or any external system should use generic Atom operations:</p>
          <ul class="help">
            <li>domain -> createTenant</li>
            <li>client -> createEntity with profile client under kind device</li>
            <li>channel -> createResource with kind "channel"</li>
            <li>connection -> createPolicy for publish/subscribe</li>
          </ul>
          <p class="help">Do not add GraphQL aliases for these.</p>
        </section>
        <section class="nav-section">
          <h2>Types</h2>
          <div id="objectTypes" class="type-list"></div>
          <h3>Input types</h3>
          <div id="inputTypes" class="type-list"></div>
          <h3>Enums</h3>
          <div id="enumTypes" class="type-list"></div>
        </section>
      </div>
    </aside>
  </div>

  <script>
    const state = {
      schema: null,
      typeMap: new Map(),
      selectedOperation: null,
      lastResult: null,
      lastAuthzName: "authzCheck",
      tenants: [],
      profilesBySelect: new Map(),
      versionsBySelect: new Map(),
      resources: [],
      capabilities: [],
      roles: [],
      entities: [],
      groups: [],
      wizard: {}
    };

    const introspectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { ...FullType }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}`;

    const $ = (id) => document.getElementById(id);

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;"
      })[char]);
    }

    function parseJson(id) {
      const text = $(id).value.trim();
      if (!text) return {};
      try {
        return JSON.parse(text);
      } catch (err) {
        throw new Error(`${humanLabel(id)} contains invalid JSON: ${err.message}`);
      }
    }

    function humanLabel(id) {
      return id.replace(/([A-Z])/g, " $1").replace(/^./, (char) => char.toUpperCase());
    }

    function nullable(value) {
      const text = String(value ?? "").trim();
      return text ? text : null;
    }

    function selectedOrInput(selectId, inputId) {
      return nullable($(inputId).value) || nullable($(selectId).value);
    }

    function commaList(value) {
      return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
    }

    function endpointSafety() {
      const raw = $("endpoint").value.trim() || "/graphql";
      const url = new URL(raw, window.location.origin);
      const sameOriginGraphql = url.origin === window.location.origin && url.pathname === "/graphql";
      return {
        url,
        canSendAuth: sameOriginGraphql,
        warning: sameOriginGraphql ? "" : "Authorization is disabled unless the endpoint is same-origin /graphql."
      };
    }

    function renderEndpointWarning() {
      const safety = endpointSafety();
      $("endpointWarning").textContent = safety.warning;
      $("endpointWarning").classList.toggle("hidden", !safety.warning);
      return safety;
    }

    function authHeaders(canSendAuth) {
      const token = $("token").value.trim();
      return token && canSendAuth ? { Authorization: `Bearer ${token}` } : {};
    }

    async function requestGraphql(query, variables = {}, useAuth = true) {
      const safety = renderEndpointWarning();
      const res = await fetch(safety.url.href, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(useAuth ? authHeaders(safety.canSendAuth) : {})
        },
        body: JSON.stringify({ query, variables })
      });
      const text = await res.text();
      try {
        return JSON.parse(text);
      } catch (_) {
        throw new Error(`GraphQL endpoint returned non-JSON status ${res.status}`);
      }
    }

    function unwrapType(type) {
      let node = type;
      while (node && node.ofType) node = node.ofType;
      return node;
    }

    function typeName(type) {
      if (!type) return "";
      if (type.kind === "NON_NULL") return `${typeName(type.ofType)}!`;
      if (type.kind === "LIST") return `[${typeName(type.ofType)}]`;
      return type.name || "";
    }

    function namedType(type) {
      return unwrapType(type)?.name;
    }

    function isNonNull(type) {
      return type?.kind === "NON_NULL";
    }

    function baseType(type) {
      return state.typeMap.get(namedType(type));
    }

    function defaultValueForType(type) {
      const named = namedType(type);
      if (!isNonNull(type)) return null;
      if (["String", "ID"].includes(named)) return "";
      if (["Int", "Float"].includes(named)) return 0;
      if (named === "Boolean") return false;
      if (named === "JSON" || named === "JSONObject") return {};
      const gqlType = state.typeMap.get(named);
      if (gqlType?.kind === "ENUM") return gqlType.enumValues?.[0]?.name || "";
      if (gqlType?.kind === "INPUT_OBJECT") {
        return Object.fromEntries((gqlType.inputFields || []).map((field) => [field.name, defaultValueForType(field.type)]));
      }
      return "";
    }

    function indent(text) {
      return text.split("\n").map((line) => `  ${line}`).join("\n");
    }

    function pascal(name) {
      return name.charAt(0).toUpperCase() + name.slice(1);
    }

    function responseFieldsFor(type) {
      const gqlType = baseType(type);
      return (gqlType?.fields || []).filter((field) => !field.name.startsWith("__"));
    }

    function defaultReturnSelection(type, depth = 0) {
      const fields = responseFieldsFor(type);
      if (!fields.length) return "";
      const scalarFields = fields.filter((field) => ["SCALAR", "ENUM"].includes(unwrapType(field.type)?.kind));
      const selected = scalarFields.length ? scalarFields : fields.slice(0, 8);
      return selected.map((field) => {
        const kind = unwrapType(field.type)?.kind;
        if (["OBJECT", "INTERFACE"].includes(kind) && depth < 1) {
          const nested = defaultReturnSelection(field.type, depth + 1);
          return nested ? `${field.name} {\n${indent(nested)}\n}` : field.name;
        }
        return field.name;
      }).join("\n");
    }

    function operationText(kind, op, selectedFields = null) {
      const args = op.args || [];
      const vars = args.map((arg) => `$${arg.name}: ${typeName(arg.type)}`).join(", ");
      const argText = args.map((arg) => `${arg.name}: $${arg.name}`).join(", ");
      const selection = selectedFields ? selectedFields.join("\n") : defaultReturnSelection(op.type);
      const header = `${kind} ${pascal(op.name)}${vars ? `(${vars})` : ""}`;
      const call = `${op.name}${argText ? `(${argText})` : ""}`;
      if (!selection) return `${header} {\n  ${call}\n}`;
      return `${header} {\n  ${call} {\n${indent(indent(selection))}\n  }\n}`;
    }

    function variableSkeleton(op) {
      return Object.fromEntries((op.args || []).map((arg) => [arg.name, defaultValueForType(arg.type)]));
    }

    function operationMatches(op, search) {
      if (!search) return true;
      const haystack = [
        op.name,
        typeName(op.type),
        ...(op.args || []).map((arg) => `${arg.name} ${typeName(arg.type)}`)
      ].join(" ").toLowerCase();
      return haystack.includes(search.toLowerCase());
    }

    function renderOperationList(targetId, kind, rootTypeName) {
      const root = state.typeMap.get(rootTypeName);
      const target = $(targetId);
      const search = $("schemaSearch").value.trim();
      target.innerHTML = "";
      for (const op of (root?.fields || []).filter((field) => operationMatches(field, search))) {
        const button = document.createElement("button");
        button.className = "operation-button";
        const args = (op.args || []).map((arg) => `${arg.name}: ${typeName(arg.type)} (${isNonNull(arg.type) ? "required" : "optional"})`).join(", ") || "no arguments";
        button.innerHTML = `<strong>${escapeHtml(op.name)}</strong><span>${escapeHtml(args)} -> ${escapeHtml(typeName(op.type))}</span>`;
        button.addEventListener("click", () => selectOperation(kind, op));
        target.appendChild(button);
      }
      if (!target.children.length) {
        target.innerHTML = `<span class="help">No ${kind} operations match the current search.</span>`;
      }
    }

    function typeMatches(type, search) {
      if (!search) return true;
      return type.name?.toLowerCase().includes(search.toLowerCase());
    }

    function renderTypeLists() {
      const search = $("schemaSearch").value.trim();
      const types = Array.from(state.typeMap.values())
        .filter((type) => type.name && !type.name.startsWith("__") && typeMatches(type, search));
      $("objectTypes").innerHTML = types
        .filter((type) => type.kind === "OBJECT")
        .map((type) => `<span class="pill">${escapeHtml(type.name)}</span>`)
        .join("");
      $("inputTypes").innerHTML = types
        .filter((type) => type.kind === "INPUT_OBJECT")
        .map((type) => `<span class="pill">${escapeHtml(type.name)}</span>`)
        .join("");
      $("enumTypes").innerHTML = types
        .filter((type) => type.kind === "ENUM")
        .map((type) => `<span class="pill">${escapeHtml(type.name)}</span>`)
        .join("");
    }

    function renderSchema() {
      if (!state.schema) return;
      renderOperationList("queryOps", "query", state.schema.queryType.name);
      renderOperationList("mutationOps", "mutation", state.schema.mutationType.name);
      renderTypeLists();
    }

    function selectOperation(kind, op) {
      state.selectedOperation = { kind, op };
      const args = (op.args || []).map((arg) => `<span class="badge ${isNonNull(arg.type) ? "warn" : ""}">${escapeHtml(arg.name)}: ${escapeHtml(typeName(arg.type))}</span>`).join(" ");
      $("selectedOperation").innerHTML = `<strong>${kind} ${escapeHtml(op.name)}</strong><div class="status-row" style="margin-top: 8px;">${args || '<span class="badge">No arguments</span>'}<span class="badge">returns ${escapeHtml(typeName(op.type))}</span></div>`;
      $("queryEditor").value = operationText(kind, op);
      $("variablesEditor").value = JSON.stringify(variableSkeleton(op), null, 2);
      renderReturnFieldSelector(op);
      showScreen("advanced");
    }

    function renderReturnFieldSelector(op) {
      const target = $("returnFields");
      const fields = responseFieldsFor(op.type);
      target.innerHTML = "";
      target.classList.toggle("hidden", !fields.length);
      if (!fields.length) return;
      const defaults = new Set(defaultReturnSelection(op.type).split(/\s+/).filter(Boolean));
      for (const field of fields) {
        const label = document.createElement("label");
        const checked = defaults.has(field.name) ? "checked" : "";
        label.innerHTML = `<input type="checkbox" value="${escapeHtml(field.name)}" ${checked}> ${escapeHtml(field.name)}`;
        label.querySelector("input").addEventListener("change", regenerateSelection);
        target.appendChild(label);
      }
    }

    function regenerateSelection() {
      const current = state.selectedOperation;
      if (!current) return;
      const selected = Array.from($("returnFields").querySelectorAll("input:checked")).map((input) => input.value);
      if (selected.length) $("queryEditor").value = operationText(current.kind, current.op, selected);
    }

    function updateStatus() {
      const schemaLoaded = Boolean(state.schema);
      const tokenPresent = Boolean($("token").value.trim());
      const safety = renderEndpointWarning();
      $("connectionStatus").innerHTML = `
        <span class="badge ${safety.canSendAuth ? "ok" : "warn"}">${escapeHtml(safety.url.pathname || "/graphql")}</span>
        <span class="badge ${schemaLoaded ? "ok" : "warn"}">${schemaLoaded ? "Schema loaded" : "Schema not loaded"}</span>
        <span class="badge ${tokenPresent ? "ok" : "warn"}">${tokenPresent ? "Token ready" : "Not authenticated"}</span>
        <span class="badge ${safety.canSendAuth ? "ok" : "warn"}">${safety.canSendAuth ? "Auth header allowed" : "Auth header blocked"}</span>
      `;
    }

    async function loadSchema() {
      $("schemaStatus").innerHTML = `<span class="badge warn">Loading schema</span>`;
      updateStatus();
      try {
        const result = await requestGraphql(introspectionQuery, {}, false);
        if (result.errors?.length) throw new Error(result.errors.map((err) => err.message).join("; "));
        state.schema = result.data.__schema;
        state.typeMap = new Map(state.schema.types.map((type) => [type.name, type]));
        renderSchema();
        $("schemaStatus").innerHTML = `<span class="badge ok">Loaded ${state.schema.types.length} types</span>`;
      } catch (err) {
        $("schemaStatus").innerHTML = `<span class="badge error">${escapeHtml(err.message)}</span>`;
      }
      updateStatus();
    }

    function setPreview(query, variables, queryTarget, variablesTarget) {
      $(queryTarget).textContent = query;
      $(variablesTarget).textContent = JSON.stringify(variables, null, 2);
    }

    function setAdvancedOperation(query, variables) {
      $("queryEditor").value = query;
      $("variablesEditor").value = JSON.stringify(variables, null, 2);
    }

    function summarizeErrors(result) {
      return result.errors?.map((err) => err.message).join("; ") || "";
    }

    function writeRaw(targetId, result) {
      $(targetId).textContent = JSON.stringify(result, null, 2);
      state.lastResult = result;
    }

    function idFrom(value) {
      return value?.id || value?.entityId || value?.credentialId || null;
    }

    function resultSummary(result, dataKey, noun, nextText) {
      const errors = summarizeErrors(result);
      if (errors) return `<span class="badge error">Error</span> ${escapeHtml(errors)}`;
      const value = result.data?.[dataKey];
      const id = idFrom(value);
      const idText = id ? ` ID: <code>${escapeHtml(id)}</code>.` : "";
      return `<span class="badge ok">Success</span> ${escapeHtml(noun)} completed.${idText} ${escapeHtml(nextText || "")}`;
    }

    async function runPreviewed(builder, queryTarget, variablesTarget, resultTarget, summaryTarget, dataKey, noun, nextText, afterSuccess = null) {
      try {
        const built = builder();
        setPreview(built.query, built.variables, queryTarget, variablesTarget);
        setAdvancedOperation(built.query, built.variables);
        const result = await requestGraphql(built.query, built.variables, built.useAuth !== false);
        writeRaw(resultTarget, result);
        $(summaryTarget).innerHTML = resultSummary(result, dataKey, noun, nextText);
        if (!result.errors?.length && afterSuccess) afterSuccess(result);
        return !result.errors?.length;
      } catch (err) {
        $(summaryTarget).innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
        return false;
      }
    }

    function previewOnly(builder, queryTarget, variablesTarget, summaryTarget, text) {
      try {
        const built = builder();
        setPreview(built.query, built.variables, queryTarget, variablesTarget);
        setAdvancedOperation(built.query, built.variables);
        $(summaryTarget).innerHTML = `<span class="badge ok">Preview ready</span> ${escapeHtml(text || "Review generated GraphQL before running.")}`;
      } catch (err) {
        $(summaryTarget).innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    function loginMutation() {
      return `mutation Login($input: LoginInput!) {
  login(input: $input) {
    token
    entityId
    sessionId
    expiresAt
  }
}`;
    }

    function loginBuild() {
      return {
        query: loginMutation(),
        variables: {
          input: {
            identifier: $("loginIdentifier").value,
            secret: $("loginSecret").value,
            kind: $("loginKind").value || "password"
          }
        },
        useAuth: false
      };
    }

    async function runLogin() {
      const built = loginBuild();
      setPreview(built.query, built.variables, "loginGraphql", "loginVariables");
      const safeVariables = JSON.parse(JSON.stringify(built.variables));
      safeVariables.input.secret = safeVariables.input.secret ? "<redacted>" : "";
      $("loginVariables").textContent = JSON.stringify(safeVariables, null, 2);
      try {
        const result = await requestGraphql(built.query, built.variables, false);
        writeRaw("loginResult", result);
        const login = result.data?.login;
        if (login?.token) {
          $("token").value = login.token;
          localStorage.setItem("atom.graphql.console.token", login.token);
          $("loginSummary").innerHTML = `<span class="badge ok">Logged in</span> Entity <code>${escapeHtml(login.entityId)}</code>. Token stored in localStorage for this browser.`;
        } else {
          $("loginSummary").innerHTML = result.errors?.length ? `<span class="badge error">Error</span> ${escapeHtml(summarizeErrors(result))}` : `<span class="badge warn">No token returned</span>`;
        }
      } catch (err) {
        $("loginSummary").innerHTML = `<span class="badge error">Error</span> ${escapeHtml(err.message)}`;
      }
      updateStatus();
    }

    function clearToken() {
      $("token").value = "";
      localStorage.removeItem("atom.graphql.console.token");
      updateStatus();
    }

    function tenantMutation() {
      return `mutation CreateTenant($input: CreateTenantInput!) {
  createTenant(input: $input) {
    id
    name
    route
    status
    tags
    attributes
  }
}`;
    }

    function tenantBuild(prefix = "tenant") {
      return {
        query: tenantMutation(),
        variables: {
          input: {
            name: $(`${prefix}Name`).value,
            route: nullable($(`${prefix}Route`)?.value),
            tags: $(`${prefix}Tags`) ? commaList($(`${prefix}Tags`).value) : [],
            attributes: parseJson(`${prefix}Attributes`)
          }
        }
      };
    }

    function profileMutation() {
      return `mutation CreateProfile($input: CreateProfileInput!) {
  createProfile(input: $input) {
    id
    tenantId
    objectKind
    kind
    key
    displayName
    description
    status
  }
}`;
    }

    function profileVersionMutation() {
      return `mutation CreateProfileVersion($profileId: ID!, $input: CreateProfileVersionInput!) {
  createProfileVersion(profileId: $profileId, input: $input) {
    id
    profileId
    version
    jsonSchema
    uiSchema
    status
  }
}`;
    }

    function profileBuild() {
      return {
        query: profileMutation(),
        variables: {
          input: {
            tenantId: selectedOrInput("profileTenantSelect", "profileTenantId"),
            objectKind: $("profileObjectKind").value || "entity",
            kind: $("profileKind").value,
            key: $("profileKey").value,
            displayName: $("profileDisplayName").value,
            description: nullable($("profileDescription").value),
            status: nullable($("profileStatus").value)
          }
        }
      };
    }

    function profileVersionBuild() {
      return {
        query: profileVersionMutation(),
        variables: {
          profileId: $("profileVersionProfileId").value,
          input: {
            version: Number($("profileVersionNumber").value || 1),
            jsonSchema: parseJson("profileJsonSchema"),
            uiSchema: parseJson("profileUiSchema"),
            status: nullable($("profileVersionStatus").value)
          }
        }
      };
    }

    function entityMutation() {
      return `mutation CreateEntity($input: CreateEntityInput!) {
  createEntity(input: $input) {
    id
    kind
    profileId
    profileVersionId
    name
    tenantId
    status
    attributes
  }
}`;
    }

    function entityBuild(config = {}) {
      const selectId = config.profileSelect || "entityProfile";
      const versionId = config.versionSelect || "entityProfileVersion";
      const profileId = nullable($(selectId).value);
      const input = {
        profileId,
        profileVersionId: nullable($(versionId).value),
        name: $(config.name || "entityName").value,
        tenantId: config.tenantValue ?? selectedOrInput("entityTenantSelect", "entityTenantId"),
        attributes: config.attributesJson ? parseJson(config.attributesJson) : schemaFormAttributes("schemaForm", "entityAttributes")
      };
      if (!input.profileId) {
        delete input.profileId;
        input.kind = $(config.kind || "entityKind").value;
      }
      if (!input.profileVersionId) delete input.profileVersionId;
      return { query: entityMutation(), variables: { input } };
    }

    function resourceMutation() {
      return `mutation CreateResource($input: CreateResourceInput!) {
  createResource(input: $input) {
    id
    kind
    name
    tenantId
    ownerId
    attributes
  }
}`;
    }

    function resourceKind(prefix = "resource") {
      const preset = $(`${prefix}KindPreset`)?.value;
      if (preset && preset !== "custom") return preset;
      return $(`${prefix}KindCustom`)?.value || $(`${prefix}Kind`)?.value || "resource";
    }

    function resourceBuild(prefix = "resource") {
      return {
        query: resourceMutation(),
        variables: {
          input: {
            kind: resourceKind(prefix),
            name: nullable($(`${prefix}Name`).value),
            tenantId: prefix === "resource" ? selectedOrInput("resourceTenantSelect", "resourceTenantId") : nullable($(`${prefix}TenantId`).value),
            ownerId: nullable($(`${prefix}OwnerId`)?.value),
            attributes: parseJson(`${prefix}Attributes`)
          }
        }
      };
    }

    function policyMutation() {
      return `mutation CreatePolicy($input: CreatePolicyInput!) {
  createPolicy(input: $input) {
    id
    tenantId
    subjectKind
    subjectId
    grantKind
    grantId
    scopeKind
    scopeRef
    effect
    conditions
  }
}`;
    }

    function selectedOption(selectId) {
      return $(selectId).selectedOptions[0];
    }

    function policySubjectId() {
      return nullable($("policySubjectId").value) || nullable($("policySubjectSelect").value);
    }

    function policyGrantId() {
      return nullable($("policyGrantId").value) || nullable($("policyGrantSelect").value);
    }

    function policyScopeRef() {
      const kind = $("policyScopeKind").value;
      if (kind === "platform") return null;
      if (kind === "tenant") return nullable($("policyScopeRef").value) || nullable($("policyTenantSelect").value);
      if (kind === "object") return nullable($("policyScopeRef").value) || nullable($("policyObjectSelect").value);
      return nullable($("policyScopeRef").value);
    }

    function policyBuild() {
      return {
        query: policyMutation(),
        variables: {
          input: {
            tenantId: nullable($("policyTenantSelect").value),
            subjectKind: $("policySubjectKind").value,
            subjectId: policySubjectId(),
            grantKind: $("policyGrantKind").value,
            grantId: policyGrantId(),
            scopeKind: $("policyScopeKind").value,
            scopeRef: policyScopeRef(),
            effect: $("policyEffect").value,
            conditions: parseJson("policyConditions")
          }
        }
      };
    }

    function setupPolicyBuild() {
      return {
        query: policyMutation(),
        variables: {
          input: {
            tenantId: nullable($("setupPolicyTenantId").value),
            subjectKind: "entity",
            subjectId: $("setupPolicySubjectId").value,
            grantKind: "capability",
            grantId: $("setupPolicyGrantId").value,
            scopeKind: "object",
            scopeRef: $("setupPolicyResourceId").value,
            effect: $("setupPolicyEffect").value,
            conditions: parseJson("setupPolicyConditions")
          }
        }
      };
    }

    function authzMutation(name) {
      return `mutation ${pascal(name)}($input: AuthzCheckInput!) {
  ${name}(input: $input) {
    allowed
    reason
    ${name === "authzExplain" ? "subject\n    resource\n    capability\n    matchedBinding\n    evaluatedBindings" : "details"}
  }
}`;
    }

    function authzBuild(name = "authzCheck", prefix = "authz") {
      return {
        query: authzMutation(name),
        variables: {
          input: {
            subjectId: $(`${prefix}SubjectId`).value,
            action: $(`${prefix}Action`).value,
            resourceId: nullable($(`${prefix}ResourceId`).value),
            objectKind: nullable($(`${prefix}ObjectKind`)?.value),
            objectId: nullable($(`${prefix}ObjectId`)?.value),
            context: parseJson(`${prefix}Context`)
          }
        }
      };
    }

    function credentialBuild(kind) {
      if (kind === "list") {
        return {
          query: `query Credentials($entityId: ID!) {
  credentials(entityId: $entityId) {
    total
    items {
      id
      kind
      identifier
      status
      expiresAt
      createdAt
    }
  }
}`,
          variables: { entityId: $("credentialEntityId").value }
        };
      }
      if (kind === "apiKey") {
        return {
          query: `mutation CreateApiKey($entityId: ID!, $input: CreateApiKeyInput!) {
  createApiKey(entityId: $entityId, input: $input) {
    credentialId
    key
    expiresAt
  }
}`,
          variables: {
            entityId: $("credentialEntityId").value,
            input: {
              description: nullable($("apiKeyDescription").value),
              expiresAt: nullable($("apiKeyExpiresAt").value)
            }
          }
        };
      }
      if (kind === "password") {
        return {
          query: `mutation CreatePassword($entityId: ID!, $password: String!) {
  createPassword(entityId: $entityId, password: $password)
}`,
          variables: {
            entityId: $("credentialEntityId").value,
            password: $("passwordSecret").value
          }
        };
      }
      return {
        query: `mutation RevokeCredential($entityId: ID!, $credentialId: ID!) {
  revokeCredential(entityId: $entityId, credentialId: $credentialId)
}`,
        variables: {
          entityId: $("credentialEntityId").value,
          credentialId: $("credentialId").value
        }
      };
    }

    function schemaFormAttributes(formId, fallbackId) {
      const attrs = {};
      for (const input of $(formId).querySelectorAll("[data-attr]")) {
        if (input.value === "") continue;
        if (input.type === "number") attrs[input.dataset.attr] = Number(input.value);
        else if (input.type === "checkbox") attrs[input.dataset.attr] = input.checked;
        else attrs[input.dataset.attr] = input.value;
      }
      return Object.keys(attrs).length ? attrs : parseJson(fallbackId);
    }

    async function loadTenants(targetIds = ["profileTenantSelect", "entityTenantSelect", "resourceTenantSelect", "policyTenantSelect"]) {
      const query = `query TenantsForConsole {
  tenants(limit: 200) {
    items {
      id
      name
      route
      status
    }
  }
}`;
      const result = await requestGraphql(query, {});
      if (result.errors?.length) throw new Error(summarizeErrors(result));
      state.tenants = result.data?.tenants?.items || [];
      for (const id of targetIds) fillSelect(id, state.tenants, "Choose tenant", (tenant) => `${tenant.name} (${tenant.status})`, "id");
      return state.tenants;
    }

    function fillSelect(selectId, items, placeholder, labelFn, valueKey = "id") {
      const select = $(selectId);
      if (!select) return;
      select.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = placeholder;
      select.appendChild(blank);
      for (const item of items) {
        const option = document.createElement("option");
        option.value = item[valueKey] || "";
        option.textContent = labelFn(item);
        for (const [key, value] of Object.entries(item)) {
          if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
            option.dataset[key] = value;
          }
        }
        select.appendChild(option);
      }
    }

    async function loadProfilesFor(selectId, versionSelectId, kindId, tenantSelectId = null, tenantInputId = null) {
      const kind = $(kindId).value;
      const tenantId = tenantSelectId ? selectedOrInput(tenantSelectId, tenantInputId) : null;
      const query = `query EntityProfiles($kind: String, $tenantId: ID) {
  profiles(objectKind: "entity", kind: $kind, tenantId: $tenantId, status: "active", limit: 200) {
    items {
      id
      tenantId
      kind
      key
      displayName
      status
    }
  }
}`;
      const result = await requestGraphql(query, { kind, tenantId });
      if (result.errors?.length) throw new Error(summarizeErrors(result));
      const profiles = result.data?.profiles?.items || [];
      state.profilesBySelect.set(selectId, profiles);
      fillSelect(selectId, profiles, "Choose profile", (profile) => `${profile.key} - ${profile.displayName}`, "id");
      await loadProfileVersionsFor(selectId, versionSelectId);
      updateEntityBadges();
    }

    async function loadProfileVersionsFor(profileSelectId, versionSelectId) {
      const profileId = $(profileSelectId).value;
      const select = $(versionSelectId);
      select.innerHTML = `<option value="">Active/latest version</option>`;
      if (!profileId) {
        renderJsonSchemaFormFor(versionSelectId, profileSelectId);
        return;
      }
      const query = `query ProfileVersions($profileId: ID!) {
  profileVersions(profileId: $profileId) {
    id
    version
    jsonSchema
    status
  }
}`;
      const result = await requestGraphql(query, { profileId });
      if (result.errors?.length) throw new Error(summarizeErrors(result));
      const versions = (result.data?.profileVersions || []).sort((a, b) => b.version - a.version);
      state.versionsBySelect.set(versionSelectId, versions);
      for (const version of versions) {
        const option = document.createElement("option");
        option.value = version.id;
        option.textContent = `v${version.version} ${version.status}`;
        option.dataset.schema = JSON.stringify(version.jsonSchema || {});
        option.dataset.status = version.status;
        select.appendChild(option);
      }
      const activeIndex = Array.from(select.options).findIndex((option) => option.dataset.status === "active");
      select.selectedIndex = activeIndex >= 0 ? activeIndex : (select.options.length > 1 ? 1 : 0);
      renderJsonSchemaFormFor(versionSelectId, profileSelectId);
    }

    function renderJsonSchemaFormFor(versionSelectId, profileSelectId) {
      const formId = versionSelectId === "entityProfileVersion" ? "schemaForm" : null;
      if (!formId) return;
      const option = $(versionSelectId).selectedOptions[0];
      const schema = option?.dataset.schema ? JSON.parse(option.dataset.schema) : {};
      const props = schema.properties || {};
      const form = $(formId);
      form.innerHTML = "";
      for (const [name, spec] of Object.entries(props)) {
        const label = document.createElement("label");
        label.textContent = spec.title || name;
        let input;
        if (Array.isArray(spec.enum)) {
          input = document.createElement("select");
          input.innerHTML = `<option value="">Choose ${escapeHtml(name)}</option>` + spec.enum.map((item) => `<option>${escapeHtml(item)}</option>`).join("");
        } else {
          input = document.createElement("input");
          input.type = spec.type === "number" || spec.type === "integer" ? "number" : spec.type === "boolean" ? "checkbox" : "text";
          input.placeholder = spec.description || spec.type || "";
        }
        input.dataset.attr = name;
        label.appendChild(input);
        form.appendChild(label);
      }
      if (!Object.keys(props).length) {
        form.innerHTML = `<div class="help">This profile version has no simple JSON Schema properties. Use the JSON fallback below.</div>`;
      }
      updateEntityBadges();
    }

    function selectedProfile(selectId = "entityProfile") {
      const profiles = state.profilesBySelect.get(selectId) || [];
      return profiles.find((profile) => profile.id === $(selectId).value);
    }

    function updateEntityBadges() {
      const profile = selectedProfile("entityProfile");
      const version = selectedOption("entityProfileVersion");
      $("entityBadges").innerHTML = `
        <span class="badge ok">Internal kind: ${escapeHtml(profile?.kind || $("entityKind").value)}</span>
        <span class="badge">Profile subtype: ${escapeHtml(profile?.key || "not selected")}</span>
        <span class="badge ${version?.dataset.status === "active" ? "ok" : "warn"}">Version: ${escapeHtml(version?.textContent || "active/latest")}</span>
      `;
      const setupProfile = selectedProfile("setupEntityProfile");
      $("setupEntityBadges").innerHTML = `
        <span class="badge ok">Internal kind: ${escapeHtml(setupProfile?.kind || $("setupEntityKind").value)}</span>
        <span class="badge">Profile subtype: ${escapeHtml(setupProfile?.key || "not selected")}</span>
      `;
    }

    async function loadPolicySubjects() {
      const tenantId = nullable($("policyTenantSelect").value);
      if ($("policySubjectKind").value === "entity") {
        const query = `query EntitySubjects($tenantId: ID) {
  entities(tenantId: $tenantId, limit: 200) {
    items { id kind name status tenantId }
  }
}`;
        const result = await requestGraphql(query, { tenantId });
        if (result.errors?.length) throw new Error(summarizeErrors(result));
        state.entities = result.data?.entities?.items || [];
        fillSelect("policySubjectSelect", state.entities, "Choose entity", (item) => `${item.name} (${item.kind})`, "id");
      } else {
        const query = `query GroupSubjects($tenantId: ID) {
  groups(tenantId: $tenantId, limit: 200) {
    items { id name tenantId description }
  }
}`;
        const result = await requestGraphql(query, { tenantId });
        if (result.errors?.length) throw new Error(summarizeErrors(result));
        state.groups = result.data?.groups?.items || [];
        fillSelect("policySubjectSelect", state.groups, "Choose group", (item) => item.name, "id");
      }
      updatePolicyHumanSummary();
    }

    async function loadPolicyGrants() {
      if ($("policyGrantKind").value === "capability") {
        const query = `query CapabilitiesForPolicy {
  capabilities {
    items { id name resourceKind description }
  }
}`;
        const result = await requestGraphql(query, {});
        if (result.errors?.length) throw new Error(summarizeErrors(result));
        state.capabilities = result.data?.capabilities?.items || [];
        fillSelect("policyGrantSelect", state.capabilities, "Choose capability", (item) => `${item.name}${item.resourceKind ? ` (${item.resourceKind})` : ""}`, "id");
      } else {
        const query = `query RolesForPolicy($tenantId: ID) {
  roles(tenantId: $tenantId, limit: 200) {
    items { id name tenantId description }
  }
}`;
        const result = await requestGraphql(query, { tenantId: nullable($("policyTenantSelect").value) });
        if (result.errors?.length) throw new Error(summarizeErrors(result));
        state.roles = result.data?.roles?.items || [];
        fillSelect("policyGrantSelect", state.roles, "Choose role", (item) => item.name, "id");
      }
      updatePolicyHumanSummary();
    }

    async function loadPolicyObjects() {
      const query = `query ResourcesForPolicy($tenantId: ID) {
  resources(tenantId: $tenantId, limit: 200) {
    items { id kind name tenantId ownerId }
  }
}`;
      const result = await requestGraphql(query, { tenantId: nullable($("policyTenantSelect").value) });
      if (result.errors?.length) throw new Error(summarizeErrors(result));
      state.resources = result.data?.resources?.items || [];
      fillSelect("policyObjectSelect", state.resources, "Choose resource", (item) => `${item.name || item.id} (${item.kind})`, "id");
      updatePolicyHumanSummary();
    }

    function policyGrantName() {
      const selected = selectedOption("policyGrantSelect");
      return selected?.dataset.name || selected?.textContent || $("policyGrantKind").value;
    }

    function updatePolicyHumanSummary() {
      const effect = $("policyEffect").value === "deny" ? "Deny" : "Allow";
      const subject = selectedOption("policySubjectSelect")?.textContent || policySubjectId() || "subject";
      const grant = policyGrantName();
      const scope = $("policyScopeKind").value === "object"
        ? (selectedOption("policyObjectSelect")?.textContent || policyScopeRef() || "object")
        : `${$("policyScopeKind").value}${policyScopeRef() ? ` ${policyScopeRef()}` : ""}`;
      $("policyHumanSummary").innerHTML = `${effect} <strong>${escapeHtml(subject)}</strong> to <strong>${escapeHtml(grant)}</strong> on <strong>${escapeHtml(scope)}</strong>.`;
      $("setupPolicyHumanSummary").innerHTML = `${escapeHtml(effect)} subject to capability on resource <code>${escapeHtml($("setupPolicyResourceId").value || "resource id")}</code>.`;
    }

    function testThisPolicy() {
      $("authzSubjectId").value = policySubjectId() || "";
      if ($("policyGrantKind").value === "capability") $("authzAction").value = policyGrantName().split(" ")[0];
      if ($("policyScopeKind").value === "object") $("authzResourceId").value = policyScopeRef() || "";
      showScreen("authz");
      previewOnly(() => authzBuild("authzCheck"), "authzGraphql", "authzVariables", "authzNarrative", "Policy values copied into Authz builder where possible.");
    }

    function renderAuthzNarrative(result, name, targetId = "authzNarrative") {
      const errors = summarizeErrors(result);
      if (errors) {
        $(targetId).innerHTML = `<span class="badge error">Error</span> ${escapeHtml(errors)} <br>Next suggested action: verify the token and input IDs.`;
        return;
      }
      const decision = result.data?.[name];
      if (!decision) {
        $(targetId).innerHTML = `<span class="badge warn">No decision</span> GraphQL returned no ${escapeHtml(name)} payload.`;
        return;
      }
      const badge = decision.allowed ? `<span class="badge ok">Allowed</span>` : `<span class="badge error">Denied</span>`;
      const next = decision.allowed
        ? "Next suggested action: use this same subject/action/resource tuple in your application flow."
        : "Next suggested action: confirm the subject, capability action, resource, policy scope, and any deny policies.";
      const details = decision.details || decision.evaluatedBindings || {};
      $(targetId).innerHTML = `${badge} ${escapeHtml(decision.reason || "No reason returned")}<br><br><strong>Details</strong><pre>${escapeHtml(JSON.stringify(details, null, 2))}</pre><br>${escapeHtml(next)}`;
    }

    async function runAuthz(name, prefix = "authz", resultTarget = "authzResult", narrativeTarget = "authzNarrative") {
      state.lastAuthzName = name;
      const queryTarget = prefix === "authz" ? "authzGraphql" : `${prefix}Graphql`;
      const variablesTarget = prefix === "authz" ? "authzVariables" : `${prefix}Variables`;
      try {
        const built = authzBuild(name, prefix);
        setPreview(built.query, built.variables, queryTarget, variablesTarget);
        setAdvancedOperation(built.query, built.variables);
        const result = await requestGraphql(built.query, built.variables);
        writeRaw(resultTarget, result);
        renderAuthzNarrative(result, name, narrativeTarget);
      } catch (err) {
        $(narrativeTarget).innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    async function runCredential(kind) {
      try {
        const built = credentialBuild(kind);
        const safe = JSON.parse(JSON.stringify(built.variables));
        if (safe.password) safe.password = "<redacted>";
        setPreview(built.query, safe, "credentialGraphql", "credentialVariables");
        setAdvancedOperation(built.query, built.variables);
        const result = await requestGraphql(built.query, built.variables);
        writeRaw("credentialResult", result);
        $("credentialSummary").innerHTML = result.errors?.length
          ? `<span class="badge error">Error</span> ${escapeHtml(summarizeErrors(result))}`
          : `<span class="badge ok">Success</span> Credential operation completed. Review raw result for returned fields.`;
      } catch (err) {
        $("credentialSummary").innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    function showWizardStep(step) {
      document.querySelectorAll(".wizard-step").forEach((item) => item.classList.toggle("active", item.id === `wizard-step-${step}`));
      document.querySelectorAll(".wizard-tab").forEach((item) => item.classList.toggle("active", item.dataset.step === String(step)));
    }

    function copyText(text) {
      navigator.clipboard.writeText(text);
    }

    function snippetPayload(query, variables) {
      return JSON.stringify({ query, variables }, null, 2);
    }

    function curlSnippet(query, variables) {
      return `curl -sS ${endpointSafety().url.href} \\
  -H 'Content-Type: application/json' \\
  -H 'Authorization: Bearer $ATOM_TOKEN' \\
  --data '${snippetPayload(query, variables).replace(/'/g, "'\\''")}'`;
    }

    function jsSnippet(query, variables) {
      return `const response = await fetch("${endpointSafety().url.href}", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token
  },
  body: JSON.stringify(${snippetPayload(query, variables)})
});

const result = await response.json();`;
    }

    const recipes = {
      createTenant: {
        title: "Create tenant",
        fields: [
          ["name", "Tenant name", "factory-a"],
          ["route", "Route", "factory-a"],
          ["attributes", "Attributes JSON", "{}"]
        ],
        build(values) {
          return {
            query: tenantMutation(),
            variables: { input: { name: values.name, route: nullable(values.route), attributes: JSON.parse(values.attributes || "{}") } }
          };
        }
      },
      createProfile: {
        title: "Create profile",
        fields: [
          ["tenantId", "Tenant ID", ""],
          ["objectKind", "Object kind", "entity"],
          ["kind", "Internal kind", "device"],
          ["key", "Profile key", "client"],
          ["displayName", "Display name", "Client"]
        ],
        build(values) {
          return {
            query: profileMutation(),
            variables: { input: { tenantId: nullable(values.tenantId), objectKind: values.objectKind, kind: values.kind, key: values.key, displayName: values.displayName, description: null, status: "active" } }
          };
        }
      },
      createEntityFromProfile: {
        title: "Create entity from profile",
        fields: [
          ["tenantId", "Tenant ID", ""],
          ["profileId", "Profile ID", ""],
          ["profileVersionId", "Profile version ID", ""],
          ["name", "Entity name", "device-001"],
          ["attributes", "Attributes JSON", "{}"]
        ],
        build(values) {
          const input = { tenantId: nullable(values.tenantId), profileId: values.profileId, profileVersionId: nullable(values.profileVersionId), name: values.name, attributes: JSON.parse(values.attributes || "{}") };
          if (!input.profileVersionId) delete input.profileVersionId;
          return { query: entityMutation(), variables: { input } };
        }
      },
      createResource: {
        title: "Create resource",
        fields: [
          ["tenantId", "Tenant ID", ""],
          ["kind", "Resource kind", "channel"],
          ["name", "Resource name", "telemetry"],
          ["attributes", "Attributes JSON", "{\"topic\":\"telemetry\"}"]
        ],
        build(values) {
          return { query: resourceMutation(), variables: { input: { tenantId: nullable(values.tenantId), kind: values.kind, name: nullable(values.name), ownerId: null, attributes: JSON.parse(values.attributes || "{}") } } };
        }
      },
      grantCapability: {
        title: "Grant capability",
        fields: [
          ["tenantId", "Tenant ID", ""],
          ["subjectKind", "Subject kind", "entity"],
          ["subjectId", "Subject ID", ""],
          ["capabilityId", "Capability ID", ""],
          ["scopeKind", "Scope kind", "object"],
          ["scopeRef", "Scope ref", ""],
          ["conditions", "Conditions JSON", "{}"]
        ],
        build(values) {
          return { query: policyMutation(), variables: { input: { tenantId: nullable(values.tenantId), subjectKind: values.subjectKind, subjectId: values.subjectId, grantKind: "capability", grantId: values.capabilityId, scopeKind: values.scopeKind, scopeRef: nullable(values.scopeRef), effect: "allow", conditions: JSON.parse(values.conditions || "{}") } } };
        }
      },
      createApiKey: {
        title: "Create API key",
        fields: [
          ["entityId", "Entity ID", ""],
          ["description", "Description", "automation key"],
          ["expiresAt", "Expires at", ""]
        ],
        build(values) {
          return { query: credentialBuild("apiKey").query, variables: { entityId: values.entityId, input: { description: nullable(values.description), expiresAt: nullable(values.expiresAt) } } };
        }
      },
      runAuthzCheck: {
        title: "Run authz check",
        fields: [
          ["subjectId", "Subject ID", ""],
          ["action", "Action", "publish"],
          ["resourceId", "Resource ID", ""],
          ["context", "Context JSON", "{}"]
        ],
        build(values) {
          return { query: authzMutation("authzCheck"), variables: { input: { subjectId: values.subjectId, action: values.action, resourceId: nullable(values.resourceId), objectKind: null, objectId: null, context: JSON.parse(values.context || "{}") } } };
        }
      }
    };

    function renderRecipeList() {
      $("recipeSelect").innerHTML = Object.entries(recipes).map(([key, recipe]) => `<option value="${key}">${escapeHtml(recipe.title)}</option>`).join("");
      renderRecipeForm();
      renderSavedRecipes();
    }

    function renderRecipeForm() {
      const recipe = recipes[$("recipeSelect").value];
      $("recipeForm").innerHTML = recipe.fields.map(([key, label, value]) => {
        if (key.toLowerCase().includes("json") || key === "attributes" || key === "conditions" || key === "context") {
          return `<label>${escapeHtml(label)}<textarea id="recipeField-${escapeHtml(key)}" spellcheck="false">${escapeHtml(value)}</textarea></label>`;
        }
        return `<label>${escapeHtml(label)}<input id="recipeField-${escapeHtml(key)}" value="${escapeHtml(value)}" /></label>`;
      }).join("");
      generateRecipe();
    }

    function recipeValues() {
      const recipe = recipes[$("recipeSelect").value];
      return Object.fromEntries(recipe.fields.map(([key]) => [key, $(`recipeField-${key}`).value]));
    }

    function buildRecipe() {
      return recipes[$("recipeSelect").value].build(recipeValues());
    }

    function generateRecipe() {
      try {
        const built = buildRecipe();
        $("recipeGraphql").textContent = built.query;
        $("recipeVariables").textContent = JSON.stringify(built.variables, null, 2);
        $("recipeCurl").textContent = curlSnippet(built.query, built.variables);
        $("recipeJs").textContent = jsSnippet(built.query, built.variables);
        $("recipeSummary").innerHTML = `<span class="badge ok">Generated</span> Review GraphQL and variables before running.`;
      } catch (err) {
        $("recipeSummary").innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    async function runRecipe() {
      try {
        const built = buildRecipe();
        const result = await requestGraphql(built.query, built.variables);
        writeRaw("recipeResult", result);
        $("recipeSummary").innerHTML = result.errors?.length
          ? `<span class="badge error">Error</span> ${escapeHtml(summarizeErrors(result))}`
          : `<span class="badge ok">Success</span> Recipe ran successfully.`;
      } catch (err) {
        $("recipeSummary").innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    function renderSavedRecipes() {
      const saved = JSON.parse(localStorage.getItem("atom.graphql.console.recipes") || "{}");
      $("savedRecipes").innerHTML = Object.keys(saved).map((name) => `<option>${escapeHtml(name)}</option>`).join("");
    }

    function saveRecipe() {
      generateRecipe();
      const name = prompt("Recipe name");
      if (!name) return;
      const saved = JSON.parse(localStorage.getItem("atom.graphql.console.recipes") || "{}");
      saved[name] = {
        recipe: $("recipeSelect").value,
        values: recipeValues(),
        query: $("recipeGraphql").textContent,
        variables: $("recipeVariables").textContent
      };
      localStorage.setItem("atom.graphql.console.recipes", JSON.stringify(saved));
      renderSavedRecipes();
    }

    function loadSavedRecipe() {
      const saved = JSON.parse(localStorage.getItem("atom.graphql.console.recipes") || "{}");
      const item = saved[$("savedRecipes").value];
      if (!item) return;
      $("recipeSelect").value = item.recipe;
      renderRecipeForm();
      for (const [key, value] of Object.entries(item.values || {})) {
        const field = $(`recipeField-${key}`);
        if (field) field.value = value;
      }
      generateRecipe();
    }

    function renderSavedExamples() {
      const examples = JSON.parse(localStorage.getItem("atom.graphql.console.examples") || "{}");
      $("savedExamples").innerHTML = Object.keys(examples).map((name) => `<option>${escapeHtml(name)}</option>`).join("");
    }

    function saveExample() {
      const name = prompt("Example name");
      if (!name) return;
      const examples = JSON.parse(localStorage.getItem("atom.graphql.console.examples") || "{}");
      examples[name] = { query: $("queryEditor").value, variables: $("variablesEditor").value };
      localStorage.setItem("atom.graphql.console.examples", JSON.stringify(examples));
      renderSavedExamples();
    }

    function loadExample() {
      const examples = JSON.parse(localStorage.getItem("atom.graphql.console.examples") || "{}");
      const selected = examples[$("savedExamples").value];
      if (!selected) return;
      $("queryEditor").value = selected.query;
      $("variablesEditor").value = selected.variables;
      showScreen("advanced");
    }

    async function runCurrent() {
      try {
        const result = await requestGraphql($("queryEditor").value, JSON.parse($("variablesEditor").value || "{}"));
        writeRaw("responseViewer", result);
        $("responseStatus").className = result.errors?.length ? "badge error" : "badge ok";
        $("responseStatus").textContent = result.errors?.length ? "GraphQL error" : "Success";
        $("responseSummary").innerHTML = result.errors?.length
          ? `<span class="badge error">Error</span> ${escapeHtml(summarizeErrors(result))}`
          : `<span class="badge ok">Success</span> Operation completed.`;
      } catch (err) {
        $("responseStatus").className = "badge error";
        $("responseStatus").textContent = "Input error";
        $("responseSummary").innerHTML = `<span class="badge error">Input error</span> ${escapeHtml(err.message)}`;
      }
    }

    function generatePrompt() {
      const queries = (state.typeMap.get(state.schema?.queryType?.name)?.fields || []).map((field) => field.name);
      const mutations = (state.typeMap.get(state.schema?.mutationType?.name)?.fields || []).map((field) => field.name);
      const enums = Array.from(state.typeMap.values()).filter((type) => type.kind === "ENUM").map((type) => `${type.name}: ${(type.enumValues || []).map((item) => item.name).join(", ")}`);
      const context = {
        tenantId: selectedOrInput("entityTenantSelect", "entityTenantId") || nullable($("resourceTenantId").value) || nullable($("policyTenantSelect").value),
        entityKind: $("entityKind").value,
        profileId: nullable($("entityProfile").value),
        profileVersionId: nullable($("entityProfileVersion").value),
        resourceKind: resourceKind("resource"),
        resourceId: nullable($("authzResourceId").value) || nullable($("policyObjectSelect").value),
        subjectId: nullable($("authzSubjectId").value) || policySubjectId()
      };
      $("assistantPrompt").textContent = `You are helping generate generic Atom GraphQL.

Schema summary:
Queries: ${queries.join(", ")}
Mutations: ${mutations.join(", ")}
Enums:
${enums.join("\n")}

Selected context:
${JSON.stringify(context, null, 2)}

Atom model rules:
- Use GraphQL introspection and Atom GraphQL operations only.
- Use createTenant for domain-like isolation boundaries.
- Use createEntity for people, devices, services, workloads, and applications.
- Use createResource for protected objects, including kind "channel" when needed.
- Use createPolicy for access grants and connections.
- kind is Atom internal runtime/authz kind.
- profile is the user or domain subtype/schema.
- profileVersion is validation and history only.
- Do not invent external-system GraphQL aliases.

User request:
${$("assistantRequest").value}

Expected response format:
GraphQL operation:
<query or mutation>

Variables JSON:
{}

Explanation:
<plain-language explanation and assumptions>`;
    }

    function showScreen(name) {
      document.querySelectorAll(".screen").forEach((screen) => screen.classList.toggle("active", screen.id === `screen-${name}`));
      document.querySelectorAll(".nav-button").forEach((button) => button.classList.toggle("active", button.dataset.screen === name));
    }

    function wire(id, event, handler) {
      const node = $(id);
      if (node) node.addEventListener(event, handler);
    }

    document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => showScreen(button.dataset.screen)));
    document.querySelectorAll(".wizard-tab, .next-step").forEach((button) => button.addEventListener("click", () => showWizardStep(button.dataset.step)));

    wire("endpoint", "input", updateStatus);
    wire("token", "input", updateStatus);
    wire("refreshSchema", "click", loadSchema);
    wire("clearToken", "click", clearToken);
    wire("schemaSearch", "input", renderSchema);
    wire("copyQuery", "click", () => copyText($("queryEditor").value));
    wire("runOperation", "click", runCurrent);
    wire("saveExample", "click", saveExample);
    wire("loadExample", "click", loadExample);

    wire("runLogin", "click", runLogin);
    wire("copyLoginMutation", "click", () => copyText(loginMutation()));

    wire("previewSetupTenant", "click", () => previewOnly(() => tenantBuild("setupTenant"), "setupTenantGraphql", "setupTenantVariables", "setupTenantSummary", "Next: run createTenant."));
    wire("runSetupTenant", "click", () => runPreviewed(() => tenantBuild("setupTenant"), "setupTenantGraphql", "setupTenantVariables", "tenantResult", "setupTenantSummary", "createTenant", "Tenant", "Next: add an entity.", (result) => {
      const tenant = result.data.createTenant;
      state.wizard.tenantId = tenant.id;
      ["setupEntityTenantId", "setupResourceTenantId", "setupPolicyTenantId"].forEach((id) => $(id).value = tenant.id);
    }));
    wire("loadSetupProfiles", "click", () => loadProfilesFor("setupEntityProfile", "setupEntityProfileVersion", "setupEntityKind").catch((err) => $("setupEntitySummary").textContent = err.message));
    wire("setupEntityKind", "change", updateEntityBadges);
    wire("setupEntityProfile", "change", () => loadProfileVersionsFor("setupEntityProfile", "setupEntityProfileVersion").catch((err) => $("setupEntitySummary").textContent = err.message));
    wire("previewSetupEntity", "click", () => previewOnly(() => entityBuild({ profileSelect: "setupEntityProfile", versionSelect: "setupEntityProfileVersion", kind: "setupEntityKind", name: "setupEntityName", tenantValue: nullable($("setupEntityTenantId").value), attributesJson: "setupEntityAttributes" }), "setupEntityGraphql", "setupEntityVariables", "setupEntitySummary", "Next: run createEntity."));
    wire("runSetupEntity", "click", () => runPreviewed(() => entityBuild({ profileSelect: "setupEntityProfile", versionSelect: "setupEntityProfileVersion", kind: "setupEntityKind", name: "setupEntityName", tenantValue: nullable($("setupEntityTenantId").value), attributesJson: "setupEntityAttributes" }), "setupEntityGraphql", "setupEntityVariables", "entityResult", "setupEntitySummary", "createEntity", "Entity", "Next: create a protected resource.", (result) => {
      const entity = result.data.createEntity;
      state.wizard.entityId = entity.id;
      ["setupPolicySubjectId", "setupAuthzSubjectId"].forEach((id) => $(id).value = entity.id);
    }));
    wire("previewSetupResource", "click", () => previewOnly(() => resourceBuild("setupResource"), "setupResourceGraphql", "setupResourceVariables", "setupResourceSummary", "Next: run createResource."));
    wire("runSetupResource", "click", () => runPreviewed(() => resourceBuild("setupResource"), "setupResourceGraphql", "setupResourceVariables", "resourceResult", "setupResourceSummary", "createResource", "Resource", "Next: grant access.", (result) => {
      const resource = result.data.createResource;
      state.wizard.resourceId = resource.id;
      ["setupPolicyResourceId", "setupAuthzResourceId"].forEach((id) => $(id).value = resource.id);
    }));
    wire("previewSetupPolicy", "click", () => { updatePolicyHumanSummary(); previewOnly(setupPolicyBuild, "setupPolicyGraphql", "setupPolicyVariables", "setupPolicySummary", "Next: run createPolicy."); });
    wire("runSetupPolicy", "click", () => runPreviewed(setupPolicyBuild, "setupPolicyGraphql", "setupPolicyVariables", "policyResult", "setupPolicySummary", "createPolicy", "Policy", "Next: test access."));
    wire("previewSetupAuthz", "click", () => previewOnly(() => authzBuild("authzCheck", "setupAuthz"), "setupAuthzGraphql", "setupAuthzVariables", "setupAuthzSummary", "Next: run authzCheck."));
    wire("runSetupAuthz", "click", () => runAuthz("authzCheck", "setupAuthz", "authzResult", "setupAuthzSummary"));

    wire("loadTenantsForProfile", "click", () => loadTenants(["profileTenantSelect"]).catch((err) => $("profileSummary").textContent = err.message));
    wire("previewProfile", "click", () => previewOnly(profileBuild, "profileGraphql", "profileVariables", "profileSummary", "Next: run createProfile."));
    wire("runProfile", "click", () => runPreviewed(profileBuild, "profileGraphql", "profileVariables", "profileResult", "profileSummary", "createProfile", "Profile", "Next: create a profile version.", (result) => {
      $("profileVersionProfileId").value = result.data.createProfile.id;
    }));
    wire("previewProfileVersion", "click", () => previewOnly(profileVersionBuild, "profileGraphql", "profileVariables", "profileSummary", "Next: run createProfileVersion."));
    wire("runProfileVersion", "click", () => runPreviewed(profileVersionBuild, "profileGraphql", "profileVariables", "profileResult", "profileSummary", "createProfileVersion", "Profile version", "Next: use Entity builder."));
    wire("refreshProfilesAfterProfile", "click", () => loadProfilesFor("entityProfile", "entityProfileVersion", "entityKind", "entityTenantSelect", "entityTenantId").catch((err) => $("profileSummary").textContent = err.message));

    wire("loadTenantsForEntity", "click", () => loadTenants(["entityTenantSelect"]).catch((err) => $("entitySummary").textContent = err.message));
    wire("loadProfiles", "click", () => loadProfilesFor("entityProfile", "entityProfileVersion", "entityKind", "entityTenantSelect", "entityTenantId").catch((err) => $("entitySummary").textContent = err.message));
    wire("entityKind", "change", () => { updateEntityBadges(); });
    wire("entityProfile", "change", () => loadProfileVersionsFor("entityProfile", "entityProfileVersion").catch((err) => $("entitySummary").textContent = err.message));
    wire("entityProfileVersion", "change", () => renderJsonSchemaFormFor("entityProfileVersion", "entityProfile"));
    wire("previewEntity", "click", () => previewOnly(entityBuild, "entityGraphql", "entityVariables", "entitySummary", "Next: run createEntity."));
    wire("runEntity", "click", () => runPreviewed(entityBuild, "entityGraphql", "entityVariables", "entityResult", "entitySummary", "createEntity", "Entity", "Next: create a resource or credential."));

    wire("previewTenant", "click", () => previewOnly(tenantBuild, "tenantGraphql", "tenantVariables", "tenantSummary", "Next: run createTenant."));
    wire("runTenant", "click", () => runPreviewed(tenantBuild, "tenantGraphql", "tenantVariables", "tenantResult", "tenantSummary", "createTenant", "Tenant", "Next: add entities and resources."));

    wire("loadTenantsForResource", "click", () => loadTenants(["resourceTenantSelect"]).catch((err) => $("resourceSummary").textContent = err.message));
    wire("previewResource", "click", () => previewOnly(resourceBuild, "resourceGraphql", "resourceVariables", "resourceSummary", "Next: run createResource."));
    wire("runResource", "click", () => runPreviewed(resourceBuild, "resourceGraphql", "resourceVariables", "resourceResult", "resourceSummary", "createResource", "Resource", "Next: grant access with Policy builder."));

    wire("loadTenantsForPolicy", "click", () => loadTenants(["policyTenantSelect"]).catch((err) => $("policySummary").textContent = err.message));
    wire("loadPolicySubjects", "click", () => loadPolicySubjects().catch((err) => $("policySummary").textContent = err.message));
    wire("loadPolicyGrants", "click", () => loadPolicyGrants().catch((err) => $("policySummary").textContent = err.message));
    wire("loadPolicyObjects", "click", () => loadPolicyObjects().catch((err) => $("policySummary").textContent = err.message));
    ["policySubjectKind", "policySubjectSelect", "policySubjectId", "policyGrantKind", "policyGrantSelect", "policyGrantId", "policyScopeKind", "policyScopeRef", "policyObjectSelect", "policyEffect", "setupPolicyResourceId", "setupPolicyEffect"].forEach((id) => wire(id, "input", updatePolicyHumanSummary));
    ["policySubjectKind", "policyGrantKind", "policyScopeKind", "policyObjectSelect", "policyEffect"].forEach((id) => wire(id, "change", updatePolicyHumanSummary));
    wire("previewPolicy", "click", () => { updatePolicyHumanSummary(); previewOnly(policyBuild, "policyGraphql", "policyVariables", "policySummary", "Next: run createPolicy."); });
    wire("runPolicy", "click", () => runPreviewed(policyBuild, "policyGraphql", "policyVariables", "policyResult", "policySummary", "createPolicy", "Policy", "Next: test this policy."));
    wire("testThisPolicy", "click", testThisPolicy);

    wire("previewAuthz", "click", () => previewOnly(() => authzBuild(state.lastAuthzName), "authzGraphql", "authzVariables", "authzNarrative", "Review generated GraphQL before running."));
    wire("runAuthzCheck", "click", () => runAuthz("authzCheck"));
    wire("runAuthzExplain", "click", () => runAuthz("authzExplain"));

    wire("listCredentials", "click", () => runCredential("list"));
    wire("createApiKey", "click", () => runCredential("apiKey"));
    wire("createPassword", "click", () => runCredential("password"));
    wire("revokeCredential", "click", () => runCredential("revoke"));

    wire("recipeSelect", "change", renderRecipeForm);
    wire("generateRecipe", "click", generateRecipe);
    wire("runRecipe", "click", runRecipe);
    wire("copyRecipeGraphql", "click", () => copyText($("recipeGraphql").textContent));
    wire("copyRecipeCurl", "click", () => copyText($("recipeCurl").textContent));
    wire("copyRecipeJs", "click", () => copyText($("recipeJs").textContent));
    wire("saveRecipe", "click", saveRecipe);
    wire("loadRecipe", "click", loadSavedRecipe);

    wire("generatePrompt", "click", generatePrompt);
    wire("copyPrompt", "click", () => copyText($("assistantPrompt").textContent));

    const storedToken = localStorage.getItem("atom.graphql.console.token");
    if (storedToken) $("token").value = storedToken;
    renderSavedExamples();
    renderRecipeList();
    updateStatus();
    updateEntityBadges();
    updatePolicyHumanSummary();
    setPreview(
      loginMutation(),
      { input: { identifier: $("loginIdentifier").value, secret: "<redacted>", kind: $("loginKind").value || "password" } },
      "loginGraphql",
      "loginVariables"
    );
    loadSchema();
  </script>
</body>
</html>
"###
}

#[cfg(test)]
mod tests {
    use super::console_html;

    #[test]
    fn console_html_contains_expected_sections() {
        let html = console_html();

        for text in [
            "Atom GraphQL Console",
            "operation explorer",
            "login helper",
            "What do you want to do?",
            "API Builder",
            "entity builder",
            "resource builder",
            "policy builder",
            "authz builder",
            "Entity builder",
            "Resource builder",
            "Policy builder",
            "Authz builder",
            "Advanced GraphQL",
            "AI Assistant placeholder",
            "Schema Docs",
            "Types",
            "Input types",
            "Enums",
            "Guided setup wizard",
            "Manage credentials",
        ] {
            assert!(html.contains(text), "missing {text}");
        }

        assert!(html.contains("function typeName(type)"));
        assert!(html.contains("function renderOperationList(targetId, kind, rootTypeName)"));
        assert!(
            html.contains("Authorization is disabled unless the endpoint is same-origin /graphql.")
        );
        assert!(html.contains("mutation CreateProfile($input: CreateProfileInput!)"));
        assert!(html.contains(
            "mutation CreateProfileVersion($profileId: ID!, $input: CreateProfileVersionInput!)"
        ));
    }

    #[test]
    fn console_html_uses_generic_atom_operations_only() {
        let html = console_html();

        for suffix in ["Domain", "Client", "Channel"] {
            let operation = format!("create{suffix}");
            assert!(!html.contains(&operation), "unexpected {operation}");
        }
    }
}
