const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3001';

export default function robots() {
  return {
    rules: [
      {
        userAgent: '*'
      }
    ],
    sitemap: `${baseUrl}/sitemap.xml`,
    host: baseUrl
  };
}
