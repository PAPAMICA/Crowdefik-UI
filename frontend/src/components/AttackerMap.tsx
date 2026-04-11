import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { useEffect, useRef } from 'react'
import { useTheme } from '../theme'

// Fix Leaflet default icon path broken by bundlers
delete (L.Icon.Default.prototype as unknown as Record<string, unknown>)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
})

type GeoPoint = { ip: string; lat: number; lon: number; count: number; scenario: string; country: string }
type Props = { points: GeoPoint[] }

export function AttackerMap({ points }: Props) {
  const { effective } = useTheme()
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)

  // Initialize map once
  useEffect(() => {
    if (!containerRef.current || mapRef.current) return
    const map = L.map(containerRef.current, {
      center: [20, 0],
      zoom: 2,
      scrollWheelZoom: false,
      zoomControl: true,
      attributionControl: true,
    })
    mapRef.current = map
    layerRef.current = L.layerGroup().addTo(map)

    const tileUrl =
      effective === 'dark'
        ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'

    L.tileLayer(tileUrl, {
      attribution: '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>',
      maxZoom: 19,
    }).addTo(map)

    // Force redraw after mount to fix tile loading
    setTimeout(() => map.invalidateSize(), 100)

    return () => {
      map.remove()
      mapRef.current = null
      layerRef.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Update tile layer when theme changes
  useEffect(() => {
    const map = mapRef.current
    if (!map) return
    map.eachLayer((l) => { if ((l as L.TileLayer).setUrl) map.removeLayer(l) })
    const tileUrl =
      effective === 'dark'
        ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
        : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
    L.tileLayer(tileUrl, {
      attribution: '&copy; CARTO &copy; OSM',
      maxZoom: 19,
    }).addTo(map)
  }, [effective])

  // Update markers when points change
  useEffect(() => {
    const layer = layerRef.current
    if (!layer) return
    layer.clearLayers()
    const maxCount = Math.max(...points.map((p) => p.count), 1)
    points.forEach((p) => {
      const r = 6 + (p.count / maxCount) * 16
      const circle = L.circleMarker([p.lat, p.lon], {
        radius: r,
        color: '#ef4444',
        fillColor: '#ef4444',
        fillOpacity: 0.6,
        weight: 1,
      })
      circle.bindPopup(
        `<div style="font-size:12px">
          <div style="font-family:monospace;font-weight:bold">${p.ip}</div>
          ${p.country ? `<div>${p.country}</div>` : ''}
          ${p.scenario ? `<div style="color:#64748b">${p.scenario}</div>` : ''}
          <div>${p.count} alert${p.count > 1 ? 's' : ''}</div>
        </div>`,
      )
      layer.addLayer(circle)
    })
  }, [points])

  return (
    <div
      ref={containerRef}
      style={{ height: '340px', width: '100%', borderRadius: '16px', overflow: 'hidden', zIndex: 0 }}
    />
  )
}
