export const metadata = {
  title: 'ML-WAF Dashboard',
  description: 'Machine Learning Web Application Firewall',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{margin: 0, padding: 0, fontFamily: 'system-ui, -apple-system, sans-serif'}}>
        {children}
      </body>
    </html>
  )
}