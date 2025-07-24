export default function LogoIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect width="32" height="32" rx="6" fill="currentColor" />
      <path
        d="M8 8h16v16H8V8z"
        fill="white"
        fillOpacity="0.1"
      />
      <path
        d="M12 12h8v8h-8v-8z"
        fill="white"
        fillOpacity="0.2"
      />
      <path
        d="M14 14h4v4h-4v-4z"
        fill="white"
      />
    </svg>
  )
}
