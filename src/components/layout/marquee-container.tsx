import { MarqueeService } from '@/lib/services'
import { Marquee } from '@/features/marquee/components/marquee-ui'

export async function MarqueeContainer() {
  const messages = await MarqueeService.getActiveMessages()

  if (!messages.length) return null

  return (
    <Marquee
      messages={messages}
      speed="normal"
      pauseOnHover
      showControls
      className="sticky top-0 z-50"
    />
  )
}
