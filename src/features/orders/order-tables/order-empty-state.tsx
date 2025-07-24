import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { IconPackage, IconShoppingBag } from '@tabler/icons-react'

export function OrderEmptyState() {
  return (
    <div className="flex h-[450px] shrink-0 items-center justify-center rounded-md border border-dashed">
      <div className="mx-auto flex max-w-[420px] flex-col items-center justify-center text-center">
        <div className="flex h-20 w-20 items-center justify-center rounded-full bg-muted">
          <IconPackage className="h-10 w-10 text-muted-foreground" />
        </div>
        <h3 className="mt-4 text-lg font-semibold">No orders found</h3>
        <p className="mb-4 mt-2 text-sm text-muted-foreground">
          You haven&apos;t placed any orders yet. Start shopping to see your orders here.
        </p>
        <Button asChild>
          <Link href="/products">
            <IconShoppingBag className="mr-2 h-4 w-4" />
            Start Shopping
          </Link>
        </Button>
      </div>
    </div>
  )
}
