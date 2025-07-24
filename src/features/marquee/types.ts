import type { MarqueeMessageWithCreator } from '@/lib/services/marquee'

export interface MarqueeListingProps {
  searchParams?: {
    page?: string
    type?: string
    search?: string
  }
}

export interface MarqueeViewProps {
  marqueeId: string
}

export type { MarqueeMessageWithCreator }
