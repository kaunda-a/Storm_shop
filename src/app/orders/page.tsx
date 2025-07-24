import { Suspense } from 'react'
import type { Metadata } from 'next'
import { SearchParams } from 'nuqs/server'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import { Heading } from '@/components/ui/heading'
import { DataTableSkeleton } from '@/components/ui/table/data-table-skeleton'
import { OrderListingPage } from '@/features/orders'
import { searchParamsCache, serialize } from '@/lib/searchparams'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'

export const metadata: Metadata = {
  title: 'My Orders - Mzansi Footwear',
  description: 'View your order history, track shipments, and manage your purchases at Mzansi Footwear.',
  keywords: 'orders, order history, track order, purchase history, Mzansi Footwear',
  openGraph: {
    title: 'My Orders - Mzansi Footwear',
    description: 'View your order history and track your purchases.',
    type: 'website',
  },
  robots: {
    index: false, // Private customer data
    follow: true,
  },
}

type pageProps = {
  searchParams: Promise<SearchParams>
}

export default async function Page(props: pageProps) {
  const searchParams = await props.searchParams
  // Allow nested RSCs to access the search params (in a type-safe way)
  searchParamsCache.parse(searchParams)

  const key = serialize({ ...searchParams })

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
                  <BreadcrumbPage>Orders</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-white border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Heading
              title="My Orders"
              description="Track your orders and view your purchase history"
            />
          </div>
        </div>

        {/* Orders Table */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Suspense
            key={key}
            fallback={
              <DataTableSkeleton columnCount={6} rowCount={10} filterCount={3} />
            }
          >
            <OrderListingPage />
          </Suspense>
        </div>
      </main>
      <StoreFooter />
    </>
  )
}
