import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ['192.168.203.1', '192.168.203.134', '192.168.203.142'],
  output: process.env.DOCKER_BUILD === '1' ? 'standalone' : undefined,
  async headers() {
    return [
      {
        // HTML sayfaları: hiç cache'leme — her deploy hemen görülür
        source: '/((?!_next/static|_next/image|favicon\\.ico).*)',
        headers: [
          { key: 'Cache-Control', value: 'no-cache, no-store, must-revalidate' },
          { key: 'Pragma',        value: 'no-cache' },
          { key: 'Expires',       value: '0' },
        ],
      },
    ]
  },
  async rewrites() {
    return process.env.NODE_ENV === 'development'
      ? [
          { source: '/api/:path*', destination: 'http://localhost:8000/api/:path*' },
          { source: '/ws',         destination: 'http://localhost:8000/ws' },
        ]
      : []
  },
};

export default nextConfig;
