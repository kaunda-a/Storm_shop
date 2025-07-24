import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { IconPlus } from '@tabler/icons-react'
import Link from 'next/link'
import { ReactNode } from 'react'

interface EmptyStateProps {
  icon: ReactNode
  title: string
  description: string
  action?: {
    label: string
    href: string
  }
  className?: string
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className
}: EmptyStateProps) {
  return (
    <Card className={cn('border-dashed', className)}>
      <CardContent className="flex flex-col items-center justify-center py-16 px-6">
        <div className="mb-4 text-muted-foreground">
          {icon}
        </div>
        <h3 className="text-lg font-semibold mb-2 text-center">{title}</h3>
        <p className="text-muted-foreground text-center mb-6 max-w-md text-sm">
          {description}
        </p>
        {action && (
          <Button asChild>
            <Link href={action.href}>
              <IconPlus className="h-4 w-4 mr-2" />
              {action.label}
            </Link>
          </Button>
        )}
      </CardContent>
    </Card>
  )
}

// Pre-configured empty states for common scenarios
export function ProductsEmptyState() {
  return (
    <EmptyState
      icon={<div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
        <IconPlus className="w-8 h-8 text-muted-foreground" />
      </div>}
      title="No products found"
      description="Get started by creating your first product. Add footwear items to your inventory and start selling."
      action={{
        label: "Add First Product",
        href: "/dashboard/product/new"
      }}
    />
  )
}

export function OrdersEmptyState() {
  return (
    <EmptyState
      icon={<div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
        <IconPlus className="w-8 h-8 text-muted-foreground" />
      </div>}
      title="No orders found"
      description="Orders will appear here once customers start making purchases. You can also create manual orders."
      action={{
        label: "Create First Order",
        href: "/dashboard/orders/new"
      }}
    />
  )
}

export function UsersEmptyState() {
  return (
    <EmptyState
      icon={<div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
        <IconPlus className="w-8 h-8 text-muted-foreground" />
      </div>}
      title="No users found"
      description="Users will appear here as customers register and staff members are added to the system."
      action={{
        label: "Add First User",
        href: "/dashboard/users/new"
      }}
    />
  )
}

export function DataEmptyState({ 
  title = "No data available", 
  description = "Data will appear here once you have some activity." 
}: { 
  title?: string
  description?: string 
}) {
  return (
    <EmptyState
      icon={<div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center">
        <div className="w-8 h-8 bg-muted-foreground/20 rounded" />
      </div>}
      title={title}
      description={description}
    />
  )
}
