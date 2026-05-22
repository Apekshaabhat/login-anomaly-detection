import { useEffect, useRef } from "react";
import type { DashboardLog } from "@/lib/api";

interface Props {
  logs: DashboardLog[];
}

export default function LoginMap({ logs }: Props) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<import("leaflet").Map | null>(null);
  const layerGroupRef = useRef<import("leaflet").LayerGroup | null>(null);

  useEffect(() => {
    if (!mapRef.current || mapInstance.current) return;

    import("leaflet").then((L) => {
      // Add CSS
      if (!document.querySelector('link[href*="leaflet"]')) {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
        document.head.appendChild(link);
      }

      const worldBounds = L.latLngBounds(L.latLng(-85, -180), L.latLng(85, 180));
      const map = L.map(mapRef.current!, {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 6,
        maxBounds: worldBounds,
        maxBoundsViscosity: 1,
        zoomControl: false,
        attributionControl: false,
        worldCopyJump: false,
      });
      const markerLayer = L.layerGroup().addTo(map);

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        bounds: worldBounds,
        noWrap: true,
      }).addTo(map);
      map.setMaxBounds(worldBounds);

      mapInstance.current = map;
      layerGroupRef.current = markerLayer;
    });

    return () => {
      layerGroupRef.current?.clearLayers();
      layerGroupRef.current = null;
      mapInstance.current?.remove();
      mapInstance.current = null;
    };
  }, []);

  useEffect(() => {
    if (!mapInstance.current || !layerGroupRef.current) return;

    import("leaflet").then((L) => {
      layerGroupRef.current?.clearLayers();

      logs
        .filter((log) => log.location_lat != null && log.location_lon != null)
        .slice(0, 30)
        .forEach((log) => {
          const color = log.risk > 70 ? "#ef4444" : log.risk > 40 ? "#f59e0b" : "#22c55e";
          L.circleMarker([log.location_lat!, log.location_lon!], {
            radius: 6,
            fillColor: color,
            fillOpacity: 0.8,
            color: color,
            weight: 1,
          })
            .bindPopup(
              `<div style="font-size:12px;color:#333"><strong>${log.user}</strong><br/>${log.location}<br/>Risk: ${log.risk}%</div>`
            )
            .addTo(layerGroupRef.current!);
        });
    });
  }, [logs]);

  return <div ref={mapRef} className="w-full h-full rounded-xl" style={{ minHeight: 300 }} />;
}
