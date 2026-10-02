/**
 * Counters, gauges and one histogram type, exposed in the Prometheus text
 * format. Small enough to read in full; no client library needed for this.
 *
 * Label values come from fixed sets in the code (route patterns, status
 * codes, outcome names), never from user input, so the number of series is
 * bounded.
 */
type Labels = Record<string, string | number>;

const labelText = (labels: Labels) => {
  const entries = Object.entries(labels);
  return entries.length === 0 ? '' : `{${entries.map(([k, v]) => `${k}="${String(v).replace(/[\\"\n]/g, '_')}"`).join(',')}}`;
};

export class Metrics {
  private readonly counters = new Map<string, { help: string; values: Map<string, number> }>();
  private readonly histograms = new Map<string, { help: string; buckets: number[]; series: Map<string, { counts: number[]; sum: number; count: number }> }>();
  private readonly gauges = new Map<string, { help: string; read: () => Record<string, number> | number }>();

  counter(name: string, help: string) {
    const entry = { help, values: new Map<string, number>() };
    this.counters.set(name, entry);
    return { inc: (labels: Labels = {}, by = 1) => entry.values.set(labelText(labels), (entry.values.get(labelText(labels)) ?? 0) + by) };
  }

  histogram(name: string, help: string, buckets: number[]) {
    const entry = { help, buckets, series: new Map<string, { counts: number[]; sum: number; count: number }>() };
    this.histograms.set(name, entry);
    return {
      observe: (labels: Labels, value: number) => {
        const key = labelText(labels);
        const series = entry.series.get(key) ?? { counts: buckets.map(() => 0), sum: 0, count: 0 };
        entry.series.set(key, series);
        buckets.forEach((bound, i) => {
          if (value <= bound) series.counts[i]!++;
        });
        series.sum += value;
        series.count++;
      },
    };
  }

  /** A value read when the metrics are scraped. Return an object to label it: { queued: 3, running: 1 }. */
  gauge(name: string, help: string, read: () => Record<string, number> | number) {
    this.gauges.set(name, { help, read });
  }

  render(gaugeLabel = 'status'): string {
    const lines: string[] = [];
    for (const [name, { help, values }] of this.counters) {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} counter`);
      for (const [labels, value] of values) lines.push(`${name}${labels} ${value}`);
    }
    for (const [name, { help, read }] of this.gauges) {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`);
      const value = read();
      if (typeof value === 'number') lines.push(`${name} ${value}`);
      else for (const [label, n] of Object.entries(value)) lines.push(`${name}${labelText({ [gaugeLabel]: label })} ${n}`);
    }
    for (const [name, { help, buckets, series }] of this.histograms) {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} histogram`);
      for (const [labels, s] of series) {
        const inner = labels.slice(1, -1);
        buckets.forEach((bound, i) => lines.push(`${name}_bucket{${inner}${inner ? ',' : ''}le="${bound}"} ${s.counts[i]}`));
        lines.push(`${name}_bucket{${inner}${inner ? ',' : ''}le="+Inf"} ${s.count}`, `${name}_sum${labels} ${s.sum}`, `${name}_count${labels} ${s.count}`);
      }
    }
    return `${lines.join('\n')}\n`;
  }
}
