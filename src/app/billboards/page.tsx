import { Suspense } from 'react'
import type { Metadata } from 'next'
import { SearchParams } from 'nuqs/server'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import { Heading } from '@/components/ui/heading'
import { DataTableSkeleton } from '@/components/ui/table/data-table-skeleton'
import { BillboardListingPage } from '@/features/billboards'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'

export const metadata: Metadata = {
  title: 'Billboards - Mzansi Footwear',
  description: 'View current promotions, announcements, and campaigns at Mzansi Footwear.',
  keywords: 'billboards, promotions, announcements, campaigns, sales, Mzansi Footwear',
  openGraph: {
    title: 'Billboards - Mzansi Footwear',
    description: 'Stay updated with our latest promotions and announcements.',
    type: 'website',
  },
  robots: {
    index: true,
    follow: true,
  },
}

type pageProps = {
  searchParams: Promise<SearchParams>
}

export default async function Page(props: pageProps) {
  const searchParams = await props.searchParams

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
                  <BreadcrumbPage>Billboards</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-white border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Heading
              title="Billboards & Promotions"
              description="Stay updated with our latest promotions, announcements, and campaigns"
            />
          </div>
        </div>

        {/* Billboards List */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Suspense
            fallback={
              <DataTableSkeleton columnCount={1} rowCount={6} filterCount={0} />
            }
          >
            <BillboardListingPage searchParams={searchParams} />
          </Suspense>
        </div>
      </main>
      <StoreFooter />
    </>
  )
}
