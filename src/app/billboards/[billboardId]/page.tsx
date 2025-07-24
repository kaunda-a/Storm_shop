import { Suspense } from 'react'
import { notFound } from 'next/navigation'
import type { Metadata } from 'next'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import FormCardSkeleton from '@/components/form-card-skeleton'
import { BillboardViewPage } from '@/features/billboards'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'
import { BillboardService } from '@/lib/services/billboard'

interface BillboardPageProps {
  params: Promise<{ billboardId: string }>
}

export async function generateMetadata(props: BillboardPageProps): Promise<Metadata> {
  const params = await props.params

  try {
    const billboard = await BillboardService.getBillboardById(params.billboardId)

    if (!billboard) return notFound()

    return {
      title: `${billboard.title} - Mzansi Footwear`,
      description: billboard.description || `View details for ${billboard.title} billboard at Mzansi Footwear.`,
      keywords: `${billboard.title}, ${billboard.type.toLowerCase()}, billboard, promotion, Mzansi Footwear`,
      openGraph: {
        title: `${billboard.title} - Mzansi Footwear`,
        description: billboard.description || `View details for ${billboard.title} billboard.`,
        type: 'website',
        images: billboard.imageUrl ? [
          {
            url: billboard.imageUrl,
            width: 1200,
            height: 630,
            alt: billboard.title,
          }
        ] : undefined,
      },
      robots: {
        index: true,
        follow: true,
      },
    }
  } catch (error) {
    return notFound()
  }
}

export default async function Page(props: BillboardPageProps) {
  const params = await props.params

  // Verify billboard exists before rendering
  try {
    const billboard = await BillboardService.getBillboardById(params.billboardId)

    if (!billboard) {
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
                    <BreadcrumbLink href="/billboards">Billboards</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbPage>{billboard.title}</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
          </div>

          {/* Billboard Details */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Suspense fallback={<FormCardSkeleton />}>
              <BillboardViewPage billboardId={params.billboardId} />
            </Suspense>
          </div>
        </main>
        <StoreFooter />
      </>
    )
  } catch (error) {
    console.error('Error loading billboard:', error)
    return notFound()
  }
}
