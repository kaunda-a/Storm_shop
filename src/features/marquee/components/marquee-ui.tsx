'use client'

import { cn } from '@/lib/utils'
import { MarqueeMessageWithCreator } from '@/lib/services'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  IconX, 
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
import { useState, useEffect } from 'react'

interface MarqueeProps {
  messages: MarqueeMessageWithCreator[]
  className?: string
  speed?: 'slow' | 'normal' | 'fast'
  direction?: 'left' | 'right'
  pauseOnHover?: boolean
  showControls?: boolean
  onDismiss?: (messageId: string) => void
}

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

const typeColors: Record<string, string> = {
  INFO: 'bg-blue-500/10 text-blue-600 border-blue-200',
  SUCCESS: 'bg-green-500/10 text-green-600 border-green-200',
  WARNING: 'bg-yellow-500/10 text-yellow-600 border-yellow-200',
  ERROR: 'bg-red-500/10 text-red-600 border-red-200',
  ALERT: 'bg-orange-500/10 text-orange-600 border-orange-200',
  PROMOTION: 'bg-purple-500/10 text-purple-600 border-purple-200',
  SYSTEM: 'bg-gray-500/10 text-gray-600 border-gray-200',
  INVENTORY: 'bg-indigo-500/10 text-indigo-600 border-indigo-200',
  ORDER: 'bg-emerald-500/10 text-emerald-600 border-emerald-200'
}

const speedClasses: Record<string, string> = {
  slow: 'animate-marquee-slow',
  normal: 'animate-marquee',
  fast: 'animate-marquee-fast'
}

export function Marquee({
  messages,
  className,
  speed = 'normal',
  direction = 'left',
  pauseOnHover = true,
  showControls = true,
  onDismiss
}: MarqueeProps) {
  const [currentIndex, setCurrentIndex] = useState(0)
  const [isPaused, setIsPaused] = useState(false)

  // Auto-rotate messages
  useEffect(() => {
    if (messages.length <= 1 || isPaused) return

    const interval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % messages.length)
    }, 5000) // Change message every 5 seconds

    return () => clearInterval(interval)
  }, [messages.length, isPaused])

  if (!messages.length) return null

  const currentMessage = messages[currentIndex]
  const Icon = typeIcons[currentMessage.type] || IconInfoCircle

  return (
    <div
      className={cn(
        'relative overflow-hidden border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
        typeColors[currentMessage.type] || 'bg-gray-500/10 text-gray-600 border-gray-200',
        className
      )}
      onMouseEnter={() => pauseOnHover && setIsPaused(true)}
      onMouseLeave={() => pauseOnHover && setIsPaused(false)}
    >
      <div className='flex flex-col sm:flex-row sm:items-center sm:justify-between px-3 sm:px-4 py-2 space-y-2 sm:space-y-0'>
        {/* Message Content */}
        <div className='flex items-center space-x-2 sm:space-x-3 flex-1 min-w-0'>
          <Icon className='h-3 w-3 sm:h-4 sm:w-4 flex-shrink-0' />

          <div className='flex-1 min-w-0'>
            <div className='flex flex-wrap items-center gap-1 sm:gap-2'>
              <span className='font-medium text-xs sm:text-sm truncate'>
                {currentMessage.title}
              </span>
              <Badge variant='outline' className='text-xs'>
                Priority {currentMessage.priority}
              </Badge>
            </div>
            
            <div
              className={cn(
                'text-xs sm:text-sm whitespace-nowrap',
                !isPaused && speedClasses[speed],
                direction === 'right' && 'animate-marquee-reverse'
              )}
            >
              {currentMessage.message}
            </div>
          </div>
        </div>

        {/* Controls */}
        {showControls && (
          <div className='flex items-center space-x-1 sm:space-x-2 flex-shrink-0'>
            {/* Message Counter */}
            {messages.length > 1 && (
              <div className='text-xs text-muted-foreground hidden sm:block'>
                {currentIndex + 1} / {messages.length}
              </div>
            )}

            {/* Navigation Dots */}
            {messages.length > 1 && (
              <div className='flex space-x-1'>
                {messages.map((_, index) => (
                  <button
                    key={index}
                    onClick={() => setCurrentIndex(index)}
                    className={cn(
                      'w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full transition-colors',
                      index === currentIndex
                        ? 'bg-current'
                        : 'bg-current/30 hover:bg-current/50'
                    )}
                  />
                ))}
              </div>
            )}

            {/* Dismiss Button */}
            {onDismiss && (
              <Button
                variant='ghost'
                size='sm'
                onClick={() => onDismiss(currentMessage.id)}
                className='h-5 w-5 sm:h-6 sm:w-6 p-0 hover:bg-current/10'
              >
                <IconX className='h-2.5 w-2.5 sm:h-3 sm:w-3' />
              </Button>
            )}
          </div>
        )}
      </div>

      {/* Progress Bar for Auto-rotation */}
      {messages.length > 1 && !isPaused && (
        <div className='absolute bottom-0 left-0 h-0.5 bg-current/20 w-full'>
          <div 
            className='h-full bg-current transition-all duration-[5000ms] ease-linear'
            style={{ width: '100%' }}
          />
        </div>
      )}
    </div>
  )
}

// Simple marquee for single message
export function SimpleMarquee({
  message,
  className,
  speed = 'normal',
  direction = 'left'
}: {
  message: string
  className?: string
  speed?: 'slow' | 'normal' | 'fast'
  direction?: 'left' | 'right'
}) {
  return (
    <div className={cn('overflow-hidden bg-muted/50 border-b', className)}>
      <div
        className={cn(
          'py-1.5 sm:py-2 px-3 sm:px-4 whitespace-nowrap text-xs sm:text-sm',
          speedClasses[speed] || 'animate-marquee',
          direction === 'right' && 'animate-marquee-reverse'
        )}
      >
        {message}
      </div>
    </div>
  )
}
