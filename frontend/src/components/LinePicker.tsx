/**
 * Compact line-count selector for log pages.
 * Controls how many raw lines are tailed from the log file before filtering.
 */
export const LINE_OPTIONS = [
  { label: '1 000',  lines: 1_000 },
  { label: '5 000',  lines: 5_000 },
  { label: '10 000', lines: 10_000 },
  { label: '50 000', lines: 50_000 },
] as const

export type LineCount = typeof LINE_OPTIONS[number]['lines']

export function LinePicker({
  value,
  onChange,
}: {
  value: number
  onChange: (n: number) => void
}) {
  return (
    <div className="flex items-center gap-1 rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800">
      <span className="px-2 text-[10px] font-medium text-slate-400 select-none">Lines</span>
      {LINE_OPTIONS.map(({ label, lines }) => (
        <button
          key={lines}
          type="button"
          onClick={() => onChange(lines)}
          className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
            value === lines
              ? 'bg-violet-500 text-white shadow-sm'
              : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  )
}
