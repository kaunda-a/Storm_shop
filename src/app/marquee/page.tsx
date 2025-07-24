import { Suspense } from 'react'
import type { Metadata } from 'next'
import { SearchParams } from 'nuqs/server'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import { Heading } from '@/components/ui/heading'
import { DataTableSkeleton } from '@/components/ui/table/data-table-skeleton'
import { MarqueeListingPage } from '@/features/marquee'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'

export const metadata: Metadata = {
  title: 'Marquee Messages - Mzansi Footwear',
  description: 'View current announcements, alerts, and important messages from Mzansi Footwear.',
  keywords: 'marquee, messages, announcements, alerts, notifications, Mzansi Footwear',
  openGraph: {
    title: 'Marquee Messages - Mzansi Footwear',
    description: 'Stay updated with our latest announcements and important messages.',
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
                  <BreadcrumbPage>Messages</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-white border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Heading
              title="Marquee Messages & Announcements"
              description="Stay updated with our latest announcements, alerts, and important messages"
            />
          </div>
        </div>

        {/* Messages List */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Suspense
            fallback={
              <DataTableSkeleton columnCount={1} rowCount={6} filterCount={0} />
            }
          >
            <MarqueeListingPage searchParams={searchParams} />
          </Suspense>
        </div>
      </main>
      <StoreFooter />
    </>
  )
}
