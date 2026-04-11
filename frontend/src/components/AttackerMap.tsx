import 'leaflet/dist/leaflet.css'
import { useEffect, useState } from 'react'
import { CircleMarker, MapContainer, Popup, TileLayer } from 'react-leaflet'
import { useTheme } from '../theme'

type GeoPoint = { ip: string; lat: number; lon: number; count: number; scenario: string; country: string }

type Props = { points: GeoPoint[] }

export function AttackerMap({ points }: Props) {
  const { effective } = useTheme()
  const [mounted, setMounted] = useState(false)
  useEffect(() => setMounted(true), [])
  if (!mounted) return <div className="flex h-64 items-center justify-center text-sm text-slate-500">Loading map…</div>

  const tileUrl =
    effective === 'dark'
      ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
      : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'

  const maxCount = Math.max(...points.map((p) => p.count), 1)

  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      scrollWheelZoom={false}
      style={{ height: '340px', width: '100%', borderRadius: '16px' }}
      zoomControl={true}
    >
      <TileLayer
        url={tileUrl}
        attribution='&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
      />
      {points.map((p) => {
        const r = 6 + (p.count / maxCount) * 16
        return (
          <CircleMarker
            key={p.ip}
            center={[p.lat, p.lon]}
            radius={r}
            pathOptions={{ color: '#ef4444', fillColor: '#ef4444', fillOpacity: 0.6, weight: 1 }}
          >
            <Popup>
              <div className="text-xs">
                <div className="font-mono font-bold">{p.ip}</div>
                {p.country && <div>{p.country}</div>}
                {p.scenario && <div className="text-slate-600">{p.scenario}</div>}
                <div>{p.count} alert{p.count > 1 ? 's' : ''}</div>
              </div>
            </Popup>
          </CircleMarker>
        )
      })}
    </MapContainer>
  )
}
