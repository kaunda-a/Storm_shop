'use client';

import { cn } from '@/lib/utils';
import { IconLoader2, IconRefresh } from '@tabler/icons-react';
import { cva, type VariantProps } from 'class-variance-authority';

const loadingVariants = cva(
  'flex items-center justify-center',
  {
    variants: {
      variant: {
        default: 'text-primary',
        secondary: 'text-muted-foreground',
        destructive: 'text-destructive',
        success: 'text-green-600',
        warning: 'text-yellow-600',
      },
      size: {
        sm: 'h-4 w-4',
        default: 'h-6 w-6',
        lg: 'h-8 w-8',
        xl: 'h-12 w-12',
      },
      speed: {
        slow: 'animate-spin [animation-duration:2s]',
        default: 'animate-spin',
        fast: 'animate-spin [animation-duration:0.5s]',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
      speed: 'default',
    },
  }
);

export interface LoadingProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof loadingVariants> {
  text?: string;
  icon?: 'spinner' | 'refresh';
  overlay?: boolean;
}

export function Loading({
  className,
  variant,
  size,
  speed,
  text,
  icon = 'spinner',
  overlay = false,
  ...props
}: LoadingProps) {
  const IconComponent = icon === 'refresh' ? IconRefresh : IconLoader2;

  const content = (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2',
        overlay && 'absolute inset-0 bg-background/80 backdrop-blur-sm z-50',
        className
      )}
      {...props}
    >
      <IconComponent
        className={cn(loadingVariants({ variant, size, speed }))}
      />
      {text && (
        <p className={cn(
          'text-sm font-medium',
          variant === 'secondary' && 'text-muted-foreground',
          variant === 'destructive' && 'text-destructive',
          variant === 'success' && 'text-green-600',
          variant === 'warning' && 'text-yellow-600',
        )}>
          {text}
        </p>
      )}
    </div>
  );

  return content;
}

// Skeleton Loading Components
export function LoadingSkeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-muted', className)}
      {...props}
    />
  );
}

// Card Loading Skeleton
export function LoadingCard({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('space-y-3 p-4 border rounded-lg', className)} {...props}>
      <LoadingSkeleton className="h-4 w-3/4" />
      <LoadingSkeleton className="h-4 w-1/2" />
      <LoadingSkeleton className="h-20 w-full" />
      <div className="flex space-x-2">
        <LoadingSkeleton className="h-8 w-16" />
        <LoadingSkeleton className="h-8 w-16" />
      </div>
    </div>
  );
}

// Table Loading Skeleton
export function LoadingTable({ 
  rows = 5, 
  columns = 4, 
  className, 
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { rows?: number; columns?: number }) {
  return (
    <div className={cn('space-y-3', className)} {...props}>
      {/* Header */}
      <div className="flex space-x-4">
        {Array.from({ length: columns }).map((_, i) => (
          <LoadingSkeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex space-x-4">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <LoadingSkeleton key={colIndex} className="h-8 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

// Page Loading Component
export function LoadingPage({ 
  title = 'Loading...', 
  description,
  className,
  ...props 
}: React.HTMLAttributes<HTMLDivElement> & { 
  title?: string; 
  description?: string; 
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center min-h-[400px] space-y-4', className)} {...props}>
      <Loading size="xl" text={title} />
      {description && (
        <p className="text-sm text-muted-foreground text-center max-w-md">
          {description}
        </p>
      )}
    </div>
  );
}

// Button Loading State
export function LoadingButton({ 
  children, 
  loading = false, 
  className,
  ...props 
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean }) {
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center gap-2',
        loading && 'cursor-not-allowed opacity-70',
        className
      )}
      disabled={loading}
      {...props}
    >
      {loading && <IconLoader2 className="h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
}
