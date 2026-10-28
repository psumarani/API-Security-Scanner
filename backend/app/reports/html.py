"""HTML report renderer. Jinja2 autoescaping is enabled, so untrusted text can never inject markup."""

from typing import Any

from jinja2 import Environment, select_autoescape

_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report - {{ r.target.name }}</title>
<style>
:root{--bg:#fff;--fg:#0f172a;--muted:#475569;--line:#e2e8f0;--card:#f8fafc}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--card:#111a2e}}
body{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px}
main{max-width:980px;margin:0 auto}h1{margin:0 0 4px}h2{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.card b{display:block;font-size:22px}table{border-collapse:collapse;width:100%;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.sev-critical{background:#7f1d1d;color:#fff}.sev-high{background:#c2410c;color:#fff}.sev-medium{background:#b45309;color:#fff}
.sev-low{background:#1d4ed8;color:#fff}.sev-info{background:#475569;color:#fff}
.finding{border:1px solid var(--line);border-radius:8px;padding:14px;margin:14px 0;background:var(--card)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0}
</style></head><body><main>
<h1>API security assessment report</h1>
<p class="muted">Scan {{ r.scan.id }} &middot; generated {{ r.generated_at }} &middot; {{ r.scanner.name }} {{ r.scanner.version }}</p>

<h2>Scope and authorization</h2>
<table>
<tr><th>Target</th><td>{{ r.target.name }} ({{ r.target.id }})</td></tr>
<tr><th>Base URL</th><td>{{ r.target.base_url }}</td></tr>
<tr><th>Specification</th><td>{{ r.target.api_spec_url or 'none' }}</td></tr>
<tr><th>Authorized origin</th><td>{{ r.target.authorized_scope.get('origin') }}</td></tr>
<tr><th>Authorization confirmed</th><td>{{ r.target.authorization_confirmed_at }}{% if r.target.authorization_note %} &mdash; {{ r.target.authorization_note }}{% endif %}</td></tr>
<tr><th>Status</th><td>{{ r.scan.status }}{% if r.scan.error_summary %} &mdash; {{ r.scan.error_summary }}{% endif %}</td></tr>
<tr><th>Started / completed</th><td>{{ r.scan.started_at }} / {{ r.scan.completed_at }}</td></tr>
<tr><th>Requests made</th><td>{{ r.scan.requests_made }}</td></tr>
</table>

<h2>Summary</h2>
<div class="grid">
{% for sev, n in r.summary.by_severity.items() %}<div class="card"><span class="badge sev-{{ sev }}">{{ sev }}</span><b>{{ n }}</b></div>{% endfor %}
<div class="card"><span class="muted">Endpoints</span><b>{{ r.summary.endpoints_discovered }}</b></div>
</div>
<p class="muted">Validation status:
{% for st, n in r.summary.by_status.items() %}{{ st }}: {{ n }}{% if not loop.last %} &middot; {% endif %}{% endfor %}</p>

<h2>Configuration and module coverage</h2>
<p>Modules: {{ r.configuration.modules | join(', ') }}. Auth profiles used:
{% for p in r.configuration.auth_profiles %}{{ p.name }}{% if p.role_label %} ({{ p.role_label }}){% endif %}{% if not loop.last %}, {% endif %}{% else %}none{% endfor %}.</p>
<table><tr><th>Module</th><th>Status</th><th>Findings</th><th>Requests</th><th>Notes</th></tr>
{% for m in r.coverage.modules %}<tr><td>{{ m.name }}</td><td>{{ m.status }}</td><td>{{ m.findings }}</td><td>{{ m.requests }}</td><td>{{ m.notes | join('; ') }}</td></tr>{% endfor %}
</table>
<h3>OWASP API Security Top 10 coverage</h3>
<table><tr><th>Category</th><th>Support</th><th>Modules</th><th>Limitations</th></tr>
{% for c in r.coverage.owasp %}<tr><td>{{ c.category }} {{ c.title }}</td><td>{{ c.support }}</td><td>{{ c.modules | join(', ') or '-' }}</td><td>{{ c.limitations }}</td></tr>{% endfor %}
</table>

<h2>Findings ({{ r.findings | length }})</h2>
{% for f in r.findings %}
<div class="finding">
<h3 style="margin:0">{{ f.title }}</h3>
<p><span class="badge sev-{{ f.severity }}">{{ f.severity }}</span>
<span class="badge">{{ f.status }}</span> <span class="badge">confidence: {{ f.confidence }}</span>
<span class="badge">{{ f.category }}</span></p>
<p class="muted">{% if f.endpoint %}Endpoint: <code>{{ f.endpoint.method }} {{ f.endpoint.path }}</code>{% else %}Endpoint: general{% endif %}</p>
<p>{{ f.description }}</p>
<p><b>Remediation.</b> {{ f.remediation }}</p>
{% for ev in f.evidence %}<details><summary>Evidence {{ loop.index }}{% if ev.response_status %} (HTTP {{ ev.response_status }}){% endif %}</summary>
<pre>Request: {{ ev.request }}</pre><pre>Response: {{ ev.response }}</pre></details>{% endfor %}
</div>
{% else %}<p>No findings were recorded.</p>{% endfor %}

<h2>Endpoints</h2>
<table><tr><th>Method</th><th>Path</th><th>Auth declared</th><th>Findings</th></tr>
{% for e in r.endpoints %}<tr><td>{{ e.method }}</td><td>{{ e.path }}</td><td>{{ 'yes' if e.authentication_required else ('unknown' if e.authentication_required is none else 'no') }}</td><td>{{ e.findings }}</td></tr>{% else %}<tr><td colspan="4">None discovered.</td></tr>{% endfor %}
</table>

<h2>Inconclusive tests and scanner limitations</h2>
{% if r.inconclusive_tests %}<ul>{% for i in r.inconclusive_tests %}<li>{{ i }}</li>{% endfor %}</ul>{% else %}<p>No inconclusive tests were recorded.</p>{% endif %}
{% if r.notes %}<ul>{% for n in r.notes %}<li>{{ n }}</li>{% endfor %}</ul>{% endif %}
<ul>{% for l in r.limitations %}<li>{{ l }}</li>{% endfor %}</ul>
</main></body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(_TEMPLATE)


def render_html(report: dict[str, Any]) -> str:
    return _template.render(r=report)
