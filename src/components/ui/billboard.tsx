'use client'

import { cn } from '@/lib/utils'
import { BillboardWithCreator } from '@/lib/services'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { IconX, IconExternalLink, IconPlayerPlay } from '@tabler/icons-react'
import { useState, useEffect } from 'react'
import Image from 'next/image'

interface BillboardProps {
  billboards: BillboardWithCreator[]
  className?: string
  autoRotate?: boolean
  rotationInterval?: number
  showControls?: boolean
  onDismiss?: (billboardId: string) => void
  onAction?: (billboard: BillboardWithCreator) => void
}

const typeStyles: Record<string, string> = {
  PROMOTIONAL: 'bg-gradient-to-r from-purple-500/10 to-pink-500/10 border-purple-200',
  ANNOUNCEMENT: 'bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border-blue-200',
  PRODUCT_LAUNCH: 'bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-green-200',
  SALE: 'bg-gradient-to-r from-red-500/10 to-orange-500/10 border-red-200',
  SEASONAL: 'bg-gradient-to-r from-yellow-500/10 to-amber-500/10 border-yellow-200',
  SYSTEM_MESSAGE: 'bg-gradient-to-r from-gray-500/10 to-slate-500/10 border-gray-200',
  BRAND_CAMPAIGN: 'bg-gradient-to-r from-indigo-500/10 to-purple-500/10 border-indigo-200'
}

export function Billboard({
  billboards,
  className,
  autoRotate = true,
  rotationInterval = 8000,
  showControls = true,
  onDismiss,
  onAction
}: BillboardProps) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isPaused, setIsPaused] = useState(false)

  // Auto-rotate billboards
  useEffect(() => {
    if (!autoRotate || billboards.length <= 1 || isPaused) return

    const interval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % billboards.length)
    }, rotationInterval)

    return () => clearInterval(interval)
  }, [autoRotate, billboards.length, isPaused, rotationInterval])

  if (!billboards.length) return null

  const currentBillboard = billboards[currentIndex]

  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-lg border shadow-sm',
        typeStyles[currentBillboard.type] || 'bg-gradient-to-r from-gray-500/10 to-slate-500/10 border-gray-200',
        className
      )}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      {/* Background Image/Video */}
      {currentBillboard.imageUrl && (
        <div className='absolute inset-0'>
          <Image
            src={currentBillboard.imageUrl}
            alt={currentBillboard.title}
            fill
            className='object-cover opacity-20'
            priority
          />
          <div className='absolute inset-0 bg-gradient-to-r from-background/80 to-background/40' />
        </div>
      )}

      {currentBillboard.videoUrl && (
        <div className='absolute inset-0'>
          <video
            src={currentBillboard.videoUrl}
            autoPlay
            muted
            loop
            className='w-full h-full object-cover opacity-20'
          />
          <div className='absolute inset-0 bg-gradient-to-r from-background/80 to-background/40' />
        </div>
      )}

      {/* Content */}
      <div className='relative p-6 md:p-8'>
        <div className='flex items-start justify-between'>
          <div className='flex-1 space-y-4'>
            {/* Header */}
            <div className='space-y-2'>
              <div className='flex items-center space-x-2'>
                <Badge variant='outline' className='capitalize'>
                  {currentBillboard.type.replace('_', ' ').toLowerCase()}
                </Badge>
                {currentBillboard.endDate && (
                  <Badge variant='secondary' className='text-xs'>
                    Expires {new Date(currentBillboard.endDate).toLocaleDateString()}
                  </Badge>
                )}
              </div>
              
              <h2 className='text-2xl md:text-3xl font-bold tracking-tight'>
                {currentBillboard.title}
              </h2>
              
              {currentBillboard.description && (
                <p className='text-muted-foreground text-lg max-w-2xl'>
                  {currentBillboard.description}
                </p>
              )}
            </div>

            {/* Action Button */}
            {(currentBillboard.linkUrl || onAction) && (
              <div className='flex items-center space-x-3'>
                {currentBillboard.linkUrl && (
                  <Button
                    size='lg'
                    onClick={() => window.open(currentBillboard.linkUrl!, '_blank')}
                    className='group'
                  >
                    {currentBillboard.linkText || 'Learn More'}
                    <IconExternalLink className='ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform' />
                  </Button>
                )}
                
                {onAction && (
                  <Button
                    variant='outline'
                    size='lg'
                    onClick={() => onAction(currentBillboard)}
                  >
                    View Details
                  </Button>
                )}

                {currentBillboard.videoUrl && (
                  <Button variant='ghost' size='lg' className='group'>
                    <IconPlayerPlay className='mr-2 h-4 w-4 group-hover:scale-110 transition-transform' />
                    Watch Video
                  </Button>
                )}
              </div>
            )}
          </div>

          {/* Controls */}
          {showControls && (
            <div className='flex items-start space-x-2 ml-4'>
              {onDismiss && (
                <Button
                  variant='ghost'
                  size='sm'
                  onClick={() => onDismiss(currentBillboard.id)}
                  className='h-8 w-8 p-0 hover:bg-background/20'
                >
                  <IconX className='h-4 w-4' />
                </Button>
              )}
            </div>
          )}
        </div>

        {/* Navigation */}
        {billboards.length > 1 && (
          <div className='flex items-center justify-between mt-6'>
            <div className='flex space-x-2'>
              {billboards.map((_, index) => (
                <button
                  key={index}
                  onClick={() => setCurrentIndex(index)}
                  className={cn(
                    'w-3 h-3 rounded-full transition-all duration-200',
                    index === currentIndex
                      ? 'bg-primary scale-110'
                      : 'bg-primary/30 hover:bg-primary/50'
                  )}
                />
              ))}
            </div>

            <div className='text-sm text-muted-foreground'>
              {currentIndex + 1} of {billboards.length}
            </div>
          </div>
        )}

        {/* Progress Bar */}
        {autoRotate && billboards.length > 1 && !isPaused && (
          <div className='absolute bottom-0 left-0 h-1 bg-primary/20 w-full'>
            <div 
              className='h-full bg-primary transition-all ease-linear'
              style={{ 
                width: '100%',
                animationDuration: `${rotationInterval}ms`
              }}
            />
          </div>
        )}
      </div>
    </div>
  )
}

// Compact billboard for smaller spaces
export function CompactBillboard({
  billboard,
  className,
  onDismiss,
  onAction
}: {
  billboard: BillboardWithCreator
  className?: string
  onDismiss?: (billboardId: string) => void
  onAction?: (billboard: BillboardWithCreator) => void
}) {
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-md border p-4',
        typeStyles[billboard.type] || 'bg-gradient-to-r from-gray-500/10 to-slate-500/10 border-gray-200',
        className
      )}
    >
      <div className='flex items-center justify-between'>
        <div className='flex-1 space-y-1'>
          <div className='flex items-center space-x-2'>
            <h3 className='font-semibold text-sm'>{billboard.title}</h3>
            <Badge variant='outline' className='text-xs'>
              {billboard.type.replace('_', ' ').toLowerCase()}
            </Badge>
          </div>
          
          {billboard.description && (
            <p className='text-sm text-muted-foreground line-clamp-2'>
              {billboard.description}
            </p>
          )}

          {billboard.linkUrl && (
            <Button
              variant='link'
              size='sm'
              onClick={() => window.open(billboard.linkUrl!, '_blank')}
              className='h-auto p-0 text-xs'
            >
              {billboard.linkText || 'Learn More'}
              <IconExternalLink className='ml-1 h-3 w-3' />
            </Button>
          )}
        </div>

        {onDismiss && (
          <Button
            variant='ghost'
            size='sm'
            onClick={() => onDismiss(billboard.id)}
            className='h-6 w-6 p-0 ml-2'
          >
            <IconX className='h-3 w-3' />
          </Button>
        )}
      </div>
    </div>
  )
}
