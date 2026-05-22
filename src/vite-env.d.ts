/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ADMIN_SECRET_TOKEN?: string;
  readonly VITE_FINGERPRINTJS_PUBLIC_KEY?: string;
  readonly VITE_RRWEB_ENABLED?: string;
  readonly VITE_MAPBOX_ACCESS_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
