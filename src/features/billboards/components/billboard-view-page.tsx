import { notFound } from 'next/navigation'
import { BillboardService } from '@/lib/services/billboard'
import { Billboard } from '@/components/ui/billboard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { 
  IconCalendar, 
  IconMapPin, 
  IconUser, 
  IconExternalLink, 
  IconPhoto,
  IconVideo,
  IconLink,
  IconEye,
  IconClock
} from '@tabler/icons-react'
import { formatDate } from '@/lib/format'
import type { BillboardViewProps } from '../types'

export async function BillboardViewPage({ billboardId }: BillboardViewProps) {
  try {
    const billboard = await BillboardService.getBillboardById(billboardId)

    if (!billboard) {
      return notFound()
    }

    const isExpired = billboard.endDate && new Date(billboard.endDate) < new Date()
    const isScheduled = billboard.startDate && new Date(billboard.startDate) > new Date()

    return (
      <div className="space-y-8">
        {/* Billboard Preview */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold">Billboard Preview</h1>
            <div className="flex items-center gap-2">
              <Badge 
                variant={billboard.isActive ? "default" : "secondary"}
                className="text-xs"
              >
                {billboard.isActive ? 'Active' : 'Inactive'}
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
          
          <Billboard
            billboards={[billboard]}
            autoRotate={false}
            showControls={false}
            className="max-w-4xl"
          />
        </div>

        <Separator />

        {/* Billboard Details */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Basic Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <IconPhoto className="h-5 w-5" />
                Basic Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Title</label>
                <p className="text-lg font-semibold">{billboard.title}</p>
              </div>
              
              {billboard.description && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Description</label>
                  <p className="text-sm leading-relaxed">{billboard.description}</p>
                </div>
              )}
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Type</label>
                  <p className="capitalize">
                    {billboard.type.replace('_', ' ').toLowerCase()}
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Position</label>
                  <p className="capitalize">
                    {billboard.position.replace('_', ' ').toLowerCase()}
                  </p>
                </div>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Sort Order</label>
                <p>{billboard.sortOrder}</p>
              </div>
            </CardContent>
          </Card>

          {/* Media & Links */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <IconLink className="h-5 w-5" />
                Media & Links
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {billboard.imageUrl && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <IconPhoto className="h-4 w-4" />
                    Image
                  </label>
                  <div className="mt-2 relative h-32 rounded-lg overflow-hidden bg-muted">
                    <img
                      src={billboard.imageUrl}
                      alt={billboard.title}
                      className="w-full h-full object-cover"
                    />
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 truncate">
                    {billboard.imageUrl}
                  </p>
                </div>
              )}
              
              {billboard.videoUrl && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <IconVideo className="h-4 w-4" />
                    Video URL
                  </label>
                  <Button
                    variant="link"
                    size="sm"
                    onClick={() => window.open(billboard.videoUrl!, '_blank')}
                    className="h-auto p-0 text-xs"
                  >
                    {billboard.videoUrl}
                    <IconExternalLink className="ml-1 h-3 w-3" />
                  </Button>
                </div>
              )}
              
              {billboard.linkUrl && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                    <IconExternalLink className="h-4 w-4" />
                    Action Link
                  </label>
                  <div className="space-y-1">
                    <Button
                      variant="link"
                      size="sm"
                      onClick={() => window.open(billboard.linkUrl!, '_blank')}
                      className="h-auto p-0 text-xs"
                    >
                      {billboard.linkUrl}
                      <IconExternalLink className="ml-1 h-3 w-3" />
                    </Button>
                    {billboard.linkText && (
                      <p className="text-xs text-muted-foreground">
                        Button text: "{billboard.linkText}"
                      </p>
                    )}
                  </div>
                </div>
              )}
              
              {!billboard.imageUrl && !billboard.videoUrl && !billboard.linkUrl && (
                <div className="text-center py-8 text-muted-foreground">
                  <IconPhoto className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No media or links configured</p>
                </div>
              )}
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
                {billboard.startDate && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Start Date</label>
                    <p className="flex items-center gap-1">
                      <IconCalendar className="h-4 w-4" />
                      {formatDate(billboard.startDate)}
                    </p>
                  </div>
                )}
                
                {billboard.endDate && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">End Date</label>
                    <p className="flex items-center gap-1">
                      <IconCalendar className="h-4 w-4" />
                      {formatDate(billboard.endDate)}
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
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${
                      billboard.isActive && !isExpired && !isScheduled
                        ? 'bg-green-500'
                        : billboard.isActive && isScheduled
                        ? 'bg-yellow-500'
                        : 'bg-gray-400'
                    }`} />
                    <span className="text-sm">
                      {billboard.isActive && !isExpired && !isScheduled
                        ? 'Active & Visible'
                        : billboard.isActive && isScheduled
                        ? 'Scheduled'
                        : billboard.isActive && isExpired
                        ? 'Expired'
                        : 'Inactive'
                      }
                    </span>
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
                <p>{billboard.creator.firstName} {billboard.creator.lastName}</p>
                <p className="text-sm text-muted-foreground">{billboard.creator.email}</p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Created At</label>
                <p className="flex items-center gap-1">
                  <IconCalendar className="h-4 w-4" />
                  {formatDate(billboard.createdAt)}
                </p>
              </div>
              
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                <p className="flex items-center gap-1">
                  <IconCalendar className="h-4 w-4" />
                  {formatDate(billboard.updatedAt)}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  } catch (error) {
    console.error('Error loading billboard:', error)
    return notFound()
  }
}
