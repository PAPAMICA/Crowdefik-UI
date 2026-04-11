/**
 * Compact time-range selector for log pages.
 * Value 0 = no filter (load all).
 */
export const TIME_RANGES = [
  { label: '20 min', minutes: 20 },
  { label: '1 h',   minutes: 60 },
  { label: '6 h',   minutes: 360 },
  { label: '24 h',  minutes: 1440 },
  { label: 'All',   minutes: 0 },
] as const

export type TimeRangeMinutes = typeof TIME_RANGES[number]['minutes']

export function TimeRangePicker({
  value,
  onChange,
}: {
  value: TimeRangeMinutes | number
  onChange: (m: number) => void
}) {
  return (
    <div className="flex items-center gap-1 rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800">
      {TIME_RANGES.map(({ label, minutes }) => (
        <button
          key={minutes}
          type="button"
          onClick={() => onChange(minutes)}
          className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
            value === minutes
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
