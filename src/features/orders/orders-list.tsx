import { OrderService, OrderWithDetails } from '@/lib/services'
import { searchParamsCache } from '@/lib/searchparams'
import { OrderTable } from './order-tables'
import { columns } from './order-tables/columns'
import { auth } from '@/lib/auth'
import { redirect } from 'next/navigation'

type OrderListingPageProps = {}

export async function OrderListingPage({}: OrderListingPageProps) {
  // Get current user session
  const session = await auth()

  if (!session?.user) {
    redirect('/auth/customer-sign-in?callbackUrl=/orders')
  }

  // Get search params from cache
  const {
    page,
    perPage: pageLimit,
    search,
    status,
    paymentStatus,
    shippingStatus
  } = searchParamsCache.all()

  // Build filters for customer orders only
  const filters = {
    customerId: session.user.id, // Only show current user's orders
    ...(search && { search }),
    ...(status && { status: status as any }),
    ...(paymentStatus && { paymentStatus: paymentStatus as any }),
    ...(shippingStatus && { shippingStatus: shippingStatus as any })
  }

  // Get orders from database with advanced filtering
  const { orders, pagination } = await OrderService.getOrders({
    filters,
    page: Number(page) || 1,
    limit: Number(pageLimit) || 10
  })

  return (
    <OrderTable
      data={orders}
      totalItems={pagination.total}
      columns={columns}
    />
  )
}

