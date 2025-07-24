import { notFound } from 'next/navigation'
import { MarqueeService } from '@/lib/services/marquee'
import { Marquee } from './marquee-ui'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { 
  IconCalendar, 
  IconUser, 
  IconFlag,
  IconClock,
  IconMessageCircle,
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
import type { MarqueeViewProps } from '../types'

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

export async function MarqueeViewPage({ marqueeId }: MarqueeViewProps) {
  try {
    const message = await MarqueeService.getMessageById(marqueeId)

    if (!message) {
      return notFound()
    }

    const isExpired = message.endDate && new Date(message.endDate) < new Date()
    const isScheduled = message.startDate && new Date(message.startDate) > new Date()
    const Icon = typeIcons[message.type] || IconInfoCircle

    return (
      <div className="space-y-8">
        {/* Message Preview */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold">Marquee Message Preview</h1>
            <div className="flex items-center gap-2">
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
          </div>
          
          <Marquee
            messages={[message]}
            speed="normal"
            pauseOnHover={false}
            showControls={false}
            className="max-w-4xl border rounded-lg"
          />
        </div>

        <Separator />

        {/* Message Details */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Basic Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <IconMessageCircle className="h-5 w-5" />
                Message Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Title</label>
                <p className="text-lg font-semibold">{message.title}</p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Message</label>
                <div className="bg-muted/50 rounded-lg p-4 mt-2">
                  <p className="text-sm font-mono leading-relaxed">{message.message}</p>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Type</label>
                  <div className="flex items-center gap-2 mt-1">
                    <Icon className="h-4 w-4" />
                    <p className="capitalize">{message.type.toLowerCase()}</p>
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Priority</label>
                  <div className="flex items-center gap-2 mt-1">
                    <IconFlag className="h-4 w-4" />
                    <p>{message.priority}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Schedule & Status */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <IconClock className="h-5 w-5" />
                Schedule & Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {message.startDate && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Start Date</label>
                    <p className="flex items-center gap-1 mt-1">
                      <IconCalendar className="h-4 w-4" />
                      {formatDate(message.startDate)}
                    </p>
                  </div>
                )}
                
                {message.endDate && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">End Date</label>
                    <p className="flex items-center gap-1 mt-1">
                      <IconCalendar className="h-4 w-4" />
                      {formatDate(message.endDate)}
                      {isExpired && (
                        <Badge variant="destructive" className="text-xs ml-2">
                          Expired
                        </Badge>
                      )}
                    </p>
                  </div>
                )}
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Status</label>
                  <div className="flex items-center gap-2 mt-1">
                    <div className={`w-2 h-2 rounded-full ${
                      message.isActive && !isExpired && !isScheduled
                        ? 'bg-green-500'
                        : message.isActive && isScheduled
                        ? 'bg-yellow-500'
                        : 'bg-gray-400'
                    }`} />
                    <span className="text-sm">
                      {message.isActive && !isExpired && !isScheduled
                        ? 'Active & Visible'
                        : message.isActive && isScheduled
                        ? 'Scheduled'
                        : message.isActive && isExpired
                        ? 'Expired'
                        : 'Inactive'
                      }
                    </span>
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium text-muted-foreground">Priority Level</label>
                  <div className="mt-1">
                    <Badge variant={
                      message.priority >= 4 ? "destructive" :
                      message.priority >= 3 ? "default" :
                      message.priority >= 2 ? "secondary" : "outline"
                    }>
                      {message.priority >= 4 ? "High Priority" :
                       message.priority >= 3 ? "Medium Priority" :
                       message.priority >= 2 ? "Low Priority" : "Minimal Priority"}
                    </Badge>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Creator Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <IconUser className="h-5 w-5" />
                Creator Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Created By</label>
                <p className="mt-1">{message.creator.firstName} {message.creator.lastName}</p>
                <p className="text-sm text-muted-foreground">{message.creator.email}</p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Created At</label>
                <p className="flex items-center gap-1 mt-1">
                  <IconCalendar className="h-4 w-4" />
                  {formatDate(message.createdAt)}
                </p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                <p className="flex items-center gap-1 mt-1">
                  <IconCalendar className="h-4 w-4" />
                  {formatDate(message.updatedAt)}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Message Type Details */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Icon className="h-5 w-5" />
                Message Type Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Type</label>
                <p className="capitalize mt-1">{message.type.replace('_', ' ').toLowerCase()}</p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Description</label>
                <p className="text-sm text-muted-foreground mt-1">
                  {message.type === 'INFO' && 'General information message'}
                  {message.type === 'SUCCESS' && 'Success notification or confirmation'}
                  {message.type === 'WARNING' && 'Warning or caution message'}
                  {message.type === 'ERROR' && 'Error or problem notification'}
                  {message.type === 'ALERT' && 'Important alert requiring attention'}
                  {message.type === 'PROMOTION' && 'Promotional or marketing message'}
                  {message.type === 'SYSTEM' && 'System-related notification'}
                  {message.type === 'INVENTORY' && 'Inventory or stock-related message'}
                  {message.type === 'ORDER' && 'Order-related notification'}
                </p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Typical Use Case</label>
                <p className="text-sm text-muted-foreground mt-1">
                  {message.type === 'INFO' && 'General announcements and information sharing'}
                  {message.type === 'SUCCESS' && 'Celebrating achievements or successful operations'}
                  {message.type === 'WARNING' && 'Alerting users to potential issues or changes'}
                  {message.type === 'ERROR' && 'Notifying about system errors or problems'}
                  {message.type === 'ALERT' && 'Urgent notifications requiring immediate attention'}
                  {message.type === 'PROMOTION' && 'Marketing campaigns and promotional offers'}
                  {message.type === 'SYSTEM' && 'System maintenance and technical updates'}
                  {message.type === 'INVENTORY' && 'Stock levels and inventory management'}
                  {message.type === 'ORDER' && 'Order processing and fulfillment updates'}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  } catch (error) {
    console.error('Error loading marquee message:', error)
    return notFound()
  }
}
