import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  output: 'export',  // <--- OBLIGATORIO: Genera HTML estático
  images: {
    unoptimized: true, // <--- OBLIGATORIO: GitHub Pages no optimiza imágenes
  },
};

export default nextConfig;