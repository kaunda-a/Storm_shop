import { Suspense } from 'react'
import { notFound } from 'next/navigation'
import type { Metadata } from 'next'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import FormCardSkeleton from '@/components/form-card-skeleton'
import { OrderViewPage } from '@/features/orders'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'
import { db } from '@/lib/prisma'

interface OrderPageProps {
  params: Promise<{ orderId: string }>
}

export async function generateMetadata(props: OrderPageProps): Promise<Metadata> {
  const params = await props.params

  try {
    const order = await db.order.findUnique({
      where: { id: params.orderId },
      select: {
        orderNumber: true,
        status: true,
        totalAmount: true,
        createdAt: true
      }
    })

    if (!order) return notFound()

    return {
      title: `Order #${order.orderNumber} - Mzansi Footwear`,
      description: `View details for order #${order.orderNumber} placed on ${new Date(order.createdAt).toLocaleDateString()}. Status: ${order.status}.`,
      keywords: `order ${order.orderNumber}, order details, order tracking, Mzansi Footwear`,
      openGraph: {
        title: `Order #${order.orderNumber} - Mzansi Footwear`,
        description: `Order details and tracking information for order #${order.orderNumber}`,
        type: 'website',
      },
      robots: {
        index: false, // Private customer data
        follow: true,
      },
    }
  } catch (error) {
    return notFound()
  }
}

export default async function Page(props: OrderPageProps) {
  const params = await props.params

  // Verify order exists before rendering
  try {
    const order = await db.order.findUnique({
      where: { id: params.orderId },
      select: {
        id: true,
        orderNumber: true
      }
    })

    if (!order) {
      return notFound()
    }

    return (
      <>
        <Header />
        <main className="flex-1">
          {/* Breadcrumbs */}
          <div className="bg-gray-50 border-b">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
              <Breadcrumb>
                <BreadcrumbList>
                  <BreadcrumbItem>
                    <BreadcrumbLink href="/">Home</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbLink href="/account">Account</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbLink href="/orders">Orders</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbPage>#{order.orderNumber}</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
          </div>

          {/* Order Details */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Suspense fallback={<FormCardSkeleton />}>
              <OrderViewPage orderId={params.orderId} />
            </Suspense>
          </div>
        </main>
        <StoreFooter />
      </>
    )
  } catch (error) {
    console.error('Error loading order:', error)
    return notFound()
  }
}
