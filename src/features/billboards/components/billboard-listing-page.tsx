import { Suspense } from 'react'
import { BillboardService } from '@/lib/services/billboard'
import { Billboard, CompactBillboard } from '@/components/ui/billboard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { IconPhoto, IconExternalLink, IconCalendar, IconMapPin } from '@tabler/icons-react'
import { formatDate } from '@/lib/format'
import Link from 'next/link'
import type { BillboardListingProps } from '../types'

function BillboardListingSkeleton() {
  return (
    <div className="space-y-6">
      {[...Array(6)].map((_, i) => (
        <Card key={i}>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div className="space-y-2">
                <Skeleton className="h-6 w-48" />
                <div className="flex gap-2">
                  <Skeleton className="h-5 w-20" />
                  <Skeleton className="h-5 w-16" />
                </div>
              </div>
              <Skeleton className="h-10 w-24" />
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
              <div className="flex gap-4">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-24" />
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="text-center py-12">
      <div className="w-24 h-24 mx-auto bg-muted rounded-full flex items-center justify-center mb-4">
        <IconPhoto className="h-12 w-12 text-muted-foreground" />
      </div>
      <h3 className="text-lg font-semibold mb-2">No billboards found</h3>
      <p className="text-muted-foreground max-w-md mx-auto">
        There are currently no active billboards to display.
      </p>
    </div>
  )
}

async function BillboardListingContent({ searchParams }: BillboardListingProps) {
  const page = parseInt(searchParams?.page || '1')
  const type = searchParams?.type
  const position = searchParams?.position
  const search = searchParams?.search

  try {
    const { billboards, pagination } = await BillboardService.getAllBillboards({
      page,
      limit: 10,
      type: type as any,
      position: position as any,
    })

    // Filter by search if provided
    const filteredBillboards = search
      ? billboards.filter(billboard =>
          billboard.title.toLowerCase().includes(search.toLowerCase()) ||
          billboard.description?.toLowerCase().includes(search.toLowerCase())
        )
      : billboards

    if (!filteredBillboards.length) {
      return <EmptyState />
    }

    return (
      <div className="space-y-6">
        {/* Results Summary */}
        <div className="text-sm text-muted-foreground">
          Showing {filteredBillboards.length} of {pagination.total} billboards
          {search && <span> for "{search}"</span>}
        </div>

        {/* Billboard List */}
        <div className="space-y-6">
          {filteredBillboards.map((billboard) => (
            <Card key={billboard.id} className="overflow-hidden">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-semibold">{billboard.title}</h3>
                      <Badge variant="outline" className="capitalize">
                        {billboard.type.replace('_', ' ').toLowerCase()}
                      </Badge>
                      <Badge 
                        variant={billboard.isActive ? "default" : "secondary"}
                        className="text-xs"
                      >
                        {billboard.isActive ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <IconMapPin className="h-4 w-4" />
                        <span className="capitalize">
                          {billboard.position.replace('_', ' ').toLowerCase()}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-1">
                        <IconCalendar className="h-4 w-4" />
                        <span>Created {formatDate(billboard.createdAt)}</span>
                      </div>
                      
                      {billboard.endDate && (
                        <div className="flex items-center gap-1">
                          <IconCalendar className="h-4 w-4" />
                          <span>Expires {formatDate(billboard.endDate)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <Button variant="outline" size="sm" asChild>
                    <Link href={`/billboards/${billboard.id}`}>
                      View Details
                    </Link>
                  </Button>
                </div>
              </CardHeader>
              
              <CardContent>
                <div className="space-y-4">
                  {billboard.description && (
                    <p className="text-muted-foreground line-clamp-3">
                      {billboard.description}
                    </p>
                  )}
                  
                  {billboard.imageUrl && (
                    <div className="relative h-48 rounded-lg overflow-hidden bg-muted">
                      <img
                        src={billboard.imageUrl}
                        alt={billboard.title}
                        className="w-full h-full object-cover"
                      />
                    </div>
                  )}
                  
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Created by {billboard.creator.firstName} {billboard.creator.lastName}
                    </div>
                    
                    {billboard.linkUrl && (
                      <Button
                        variant="link"
                        size="sm"
                        onClick={() => window.open(billboard.linkUrl!, '_blank')}
                        className="h-auto p-0"
                      >
                        {billboard.linkText || 'Learn More'}
                        <IconExternalLink className="ml-1 h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Pagination would go here if needed */}
        {pagination.pages > 1 && (
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Page {page} of {pagination.pages}
            </p>
          </div>
        )}
      </div>
    )
  } catch (error) {
    console.error('Error loading billboards:', error)
    return (
      <div className="text-center py-12">
        <h3 className="text-lg font-semibold mb-2">Something went wrong</h3>
        <p className="text-muted-foreground">
          We couldn't load the billboards. Please try again later.
        </p>
      </div>
    )
  }
}

export function BillboardListingPage(props: BillboardListingProps) {
  return (
    <Suspense fallback={<BillboardListingSkeleton />}>
      <BillboardListingContent {...props} />
    </Suspense>
  )
}
