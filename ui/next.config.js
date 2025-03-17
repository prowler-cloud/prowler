/** @type {import('next').NextConfig} */

// HTTP Security Headers
const cspHeader = `
    img-src 'self';
    font-src 'self';
    style-src 'self' 'unsafe-inline';
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com;
    connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com;
    frame-src 'self' https://js.stripe.com/;
    frame-ancestors 'none';
    default-src 'self'
`


module.exports = {
  output: "standalone",
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: cspHeader.replace(/\n/g, ''),
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          }
        ],
      },
    ]
  }
};
