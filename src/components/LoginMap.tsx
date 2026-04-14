import { useEffect, useRef } from "react";
import type { LoginLog } from "@/lib/mockData";

interface Props {
  logs: LoginLog[];
}

export default function LoginMap({ logs }: Props) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<any>(null);

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

      const map = L.map(mapRef.current!, {
        center: [20, 0],
        zoom: 2,
        zoomControl: false,
        attributionControl: false,
      });

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png").addTo(map);

      logs.slice(0, 30).forEach((log) => {
        const color = log.risk > 70 ? "#ef4444" : log.risk > 40 ? "#f59e0b" : "#22c55e";
        L.circleMarker([log.lat, log.lng], {
          radius: 6,
          fillColor: color,
          fillOpacity: 0.8,
          color: color,
          weight: 1,
        })
          .bindPopup(
            `<div style="font-size:12px;color:#333"><strong>${log.user}</strong><br/>${log.location}<br/>Risk: ${log.risk}%</div>`
          )
          .addTo(map);
      });

      mapInstance.current = map;
    });

    return () => {
      mapInstance.current?.remove();
      mapInstance.current = null;
    };
  }, [logs]);

  return <div ref={mapRef} className="w-full h-full rounded-xl" style={{ minHeight: 300 }} />;
}
