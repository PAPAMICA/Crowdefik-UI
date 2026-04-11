export function CountryFlag({
  code,
  size = 20,
  className = '',
}: {
  code: string
  size?: number
  className?: string
}) {
  if (!code || code.length !== 2) return null
  const cc = code.toLowerCase()
  const h = Math.round(size * 0.75)
  return (
    <img
      src={`https://flagcdn.com/${size}x${h}/${cc}.png`}
      srcSet={`https://flagcdn.com/${size * 2}x${h * 2}/${cc}.png 2x`}
      width={size}
      height={h}
      alt={code.toUpperCase()}
      title={code.toUpperCase()}
      className={`inline-block flex-shrink-0 rounded-[2px] object-cover shadow-sm ${className}`}
      onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
    />
  )
}
