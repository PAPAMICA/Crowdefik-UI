import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { useEffect, useRef } from 'react'

type GeoPoint = { ip: string; lat: number; lon: number; count: number; scenario: string; country: string }
type Props = { points: GeoPoint[] }

export function AttackerMap({ points }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layerRef = useRef<L.LayerGroup | null>(null)
  const tileLayerRef = useRef<L.TileLayer | null>(null)

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

    // Use OpenStreetMap tiles (no subdomain / retina issues)
    const tl = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
      maxZoom: 19,
      // OSM tiles are 256×256, explicitly set
      tileSize: 256,
    })
    tl.addTo(map)
    tileLayerRef.current = tl

    // Force redraw after paint to fix tile loading
    requestAnimationFrame(() => {
      requestAnimationFrame(() => map.invalidateSize())
    })

    return () => {
      map.remove()
      mapRef.current = null
      layerRef.current = null
      tileLayerRef.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Apply dark CSS filter — no need to swap tile URL, OSM tiles work for both themes
  // The dark-mode filter in index.css handles the visual inversion

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
