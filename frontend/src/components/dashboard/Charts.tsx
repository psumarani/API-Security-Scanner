import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITIES, type FindingStatus, type Severity } from "../../types/api";
import { SEVERITY_COLORS } from "../common/Badges";
import { titleCase } from "../../utils/format";

export function SeverityChart({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const data = SEVERITIES.map((s) => ({ name: titleCase(s), severity: s, count: counts[s] ?? 0 }));
  if (data.every((d) => d.count === 0)) {
    return <p className="py-10 text-center text-sm text-slate-500">No findings to chart yet.</p>;
  }
  return (
    <div role="img" aria-label={`Findings by severity: ${data.map((d) => `${d.name} ${d.count}`).join(", ")}`} className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
          <Tooltip />
          <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]}>
            {data.map((d) => <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

const STATUS_COLORS: Record<FindingStatus, string> = {
  confirmed: "#dc2626", potential: "#d97706", informational: "#64748b", inconclusive: "#7c3aed",
};

export function StatusChart({ counts }: { counts: Record<FindingStatus, number> }) {
  const data = (Object.keys(counts) as FindingStatus[]).map((k) => ({ name: titleCase(k), key: k, value: counts[k] })).filter((d) => d.value > 0);
  if (data.length === 0) return <p className="py-10 text-center text-sm text-slate-500">No findings to chart yet.</p>;
  return (
    <div role="img" aria-label={`Findings by validation status: ${data.map((d) => `${d.name} ${d.value}`).join(", ")}`} className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} paddingAngle={2}>
            {data.map((d) => <Cell key={d.key} fill={STATUS_COLORS[d.key]} />)}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
