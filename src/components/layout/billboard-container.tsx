import { BillboardService, BillboardPosition } from '@/lib/services'
import { Billboard, CompactBillboard } from '@/components/ui/billboard'

interface BillboardContainerProps {
  position: BillboardPosition
  compact?: boolean
  className?: string
}

export async function BillboardContainer({
  position,
  compact = false,
  className
}: BillboardContainerProps) {
  try {
    const billboards = await BillboardService.getActiveBillboards(position)

    if (!billboards.length) return null

    if (compact && billboards.length === 1) {
      return (
        <CompactBillboard
          billboard={billboards[0]}
          className={className}
        />
      )
    }

    return (
      <Billboard
        billboards={billboards}
        className={className}
        autoRotate={billboards.length > 1}
        showControls
      />
    )
  } catch (error) {
    // Error handled by returning null (no billboards shown)
    return null
  }
}
