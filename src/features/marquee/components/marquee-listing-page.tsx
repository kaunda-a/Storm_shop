import { Suspense } from 'react'
import { MarqueeService } from '@/lib/services/marquee'
import { Marquee, SimpleMarquee } from './marquee-ui'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { 
  IconMessageCircle, 
  IconCalendar, 
  IconFlag,
  IconInfoCircle, 
  IconCheck, 
  IconAlertTriangle, 
  IconAlertCircle,
  IconBell,
  IconTag,
  IconServer,
  IconPackage,
  IconShoppingCart
} from '@tabler/icons-react'
import { formatDate } from '@/lib/format'
import Link from 'next/link'
import type { MarqueeListingProps } from '../types'

const typeIcons: Record<string, any> = {
  INFO: IconInfoCircle,
  SUCCESS: IconCheck,
  WARNING: IconAlertTriangle,
  ERROR: IconAlertCircle,
  ALERT: IconBell,
  PROMOTION: IconTag,
  SYSTEM: IconServer,
  INVENTORY: IconPackage,
  ORDER: IconShoppingCart
}

function MarqueeListingSkeleton() {
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
        <IconMessageCircle className="h-12 w-12 text-muted-foreground" />
      </div>
      <h3 className="text-lg font-semibold mb-2">No marquee messages found</h3>
      <p className="text-muted-foreground max-w-md mx-auto">
        There are currently no active marquee messages to display.
      </p>
    </div>
  )
}

async function MarqueeListingContent({ searchParams }: MarqueeListingProps) {
  const page = parseInt(searchParams?.page || '1')
  const type = searchParams?.type
  const search = searchParams?.search

  try {
    const { messages, pagination } = await MarqueeService.getAllMessages({
      page,
      limit: 10,
      type: type as any,
    })

    // Filter by search if provided
    const filteredMessages = search
      ? messages.filter(message =>
          message.title.toLowerCase().includes(search.toLowerCase()) ||
          message.message.toLowerCase().includes(search.toLowerCase())
        )
      : messages

    if (!filteredMessages.length) {
      return <EmptyState />
    }

    return (
      <div className="space-y-6">
        {/* Active Messages Preview */}
        {page === 1 && filteredMessages.some(msg => msg.isActive) && (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Currently Active Messages</h2>
            <div className="space-y-2">
              {filteredMessages
                .filter(msg => msg.isActive)
                .slice(0, 3)
                .map((message) => (
                  <SimpleMarquee
                    key={message.id}
                    message={`${message.title}: ${message.message}`}
                    className="rounded-lg"
                  />
                ))}
            </div>
          </div>
        )}

        {/* Results Summary */}
        <div className="text-sm text-muted-foreground">
          Showing {filteredMessages.length} of {pagination.total} messages
          {search && <span> for "{search}"</span>}
        </div>

        {/* Messages List */}
        <div className="space-y-6">
          {filteredMessages.map((message) => {
            const Icon = typeIcons[message.type] || IconInfoCircle
            const isExpired = message.endDate && new Date(message.endDate) < new Date()
            const isScheduled = message.startDate && new Date(message.startDate) > new Date()

            return (
              <Card key={message.id} className="overflow-hidden">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Icon className="h-5 w-5" />
                        <h3 className="text-xl font-semibold">{message.title}</h3>
                        <Badge variant="outline" className="capitalize">
                          {message.type.toLowerCase()}
                        </Badge>
                        <Badge 
                          variant={message.isActive ? "default" : "secondary"}
                          className="text-xs"
                        >
                          {message.isActive ? 'Active' : 'Inactive'}
                        </Badge>
                        {isExpired && (
                          <Badge variant="destructive" className="text-xs">
                            Expired
                          </Badge>
                        )}
                        {isScheduled && (
                          <Badge variant="outline" className="text-xs">
                            Scheduled
                          </Badge>
                        )}
                      </div>
                      
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1">
                          <IconFlag className="h-4 w-4" />
                          <span>Priority {message.priority}</span>
                        </div>
                        
                        <div className="flex items-center gap-1">
                          <IconCalendar className="h-4 w-4" />
                          <span>Created {formatDate(message.createdAt)}</span>
                        </div>
                        
                        {message.endDate && (
                          <div className="flex items-center gap-1">
                            <IconCalendar className="h-4 w-4" />
                            <span>Expires {formatDate(message.endDate)}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <Button variant="outline" size="sm" asChild>
                      <Link href={`/marquee/${message.id}`}>
                        View Details
                      </Link>
                    </Button>
                  </div>
                </CardHeader>
                
                <CardContent>
                  <div className="space-y-4">
                    <div className="bg-muted/50 rounded-lg p-4">
                      <p className="text-sm font-mono">{message.message}</p>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div className="text-sm text-muted-foreground">
                        Created by {message.creator.firstName} {message.creator.lastName}
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {message.isActive && !isExpired && !isScheduled && (
                          <Badge variant="default" className="text-xs">
                            Currently Visible
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
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
    console.error('Error loading marquee messages:', error)
    return (
      <div className="text-center py-12">
        <h3 className="text-lg font-semibold mb-2">Something went wrong</h3>
        <p className="text-muted-foreground">
          We couldn't load the marquee messages. Please try again later.
        </p>
      </div>
    )
  }
}

export function MarqueeListingPage(props: MarqueeListingProps) {
  return (
    <Suspense fallback={<MarqueeListingSkeleton />}>
      <MarqueeListingContent {...props} />
    </Suspense>
  )
}
