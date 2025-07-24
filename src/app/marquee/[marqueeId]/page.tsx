import { Suspense } from 'react'
import { notFound } from 'next/navigation'
import type { Metadata } from 'next'
import Header from '@/components/layout/header'
import { StoreFooter } from '@/components/layout/store-footer'
import FormCardSkeleton from '@/components/form-card-skeleton'
import { MarqueeViewPage } from '@/features/marquee'
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'
import { MarqueeService } from '@/lib/services/marquee'

interface MarqueePageProps {
  params: Promise<{ marqueeId: string }>
}

export async function generateMetadata(props: MarqueePageProps): Promise<Metadata> {
  const params = await props.params

  try {
    const message = await MarqueeService.getMessageById(params.marqueeId)

    if (!message) return notFound()

    return {
      title: `${message.title} - Mzansi Footwear`,
      description: message.message || `View details for ${message.title} message at Mzansi Footwear.`,
      keywords: `${message.title}, ${message.type.toLowerCase()}, marquee, message, announcement, Mzansi Footwear`,
      openGraph: {
        title: `${message.title} - Mzansi Footwear`,
        description: message.message || `View details for ${message.title} message.`,
        type: 'website',
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

export default async function Page(props: MarqueePageProps) {
  const params = await props.params

  // Verify message exists before rendering
  try {
    const message = await MarqueeService.getMessageById(params.marqueeId)

    if (!message) {
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
                    <BreadcrumbLink href="/marquee">Messages</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbPage>{message.title}</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
          </div>

          {/* Message Details */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Suspense fallback={<FormCardSkeleton />}>
              <MarqueeViewPage marqueeId={params.marqueeId} />
            </Suspense>
          </div>
        </main>
        <StoreFooter />
      </>
    )
  } catch (error) {
    console.error('Error loading marquee message:', error)
    return notFound()
  }
}
