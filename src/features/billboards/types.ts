import type { BillboardWithCreator } from '@/lib/services/billboard'

export interface BillboardListingProps {
  searchParams?: {
    page?: string
    type?: string
    position?: string
    search?: string
  }
}

export interface BillboardViewProps {
  billboardId: string
}

export type { BillboardWithCreator }
