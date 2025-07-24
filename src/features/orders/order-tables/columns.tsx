'use client'

import { ColumnDef } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DataTableColumnHeader } from '@/components/ui/table/data-table-column-header'
import { OrderWithDetails } from '@/lib/services'
import { formatPrice } from '@/lib/format'
import { 
  IconPackage, 
  IconTruck, 
  IconCheck, 
  IconClock, 
  IconEye,
  IconCreditCard,
  IconMapPin
} from '@tabler/icons-react'
import Link from 'next/link'

const statusConfig = {
  PENDING: { label: 'Pending', variant: 'secondary' as const, icon: IconClock },
  CONFIRMED: { label: 'Confirmed', variant: 'default' as const, icon: IconPackage },
  PROCESSING: { label: 'Processing', variant: 'default' as const, icon: IconPackage },
  SHIPPED: { label: 'Shipped', variant: 'default' as const, icon: IconTruck },
  DELIVERED: { label: 'Delivered', variant: 'default' as const, icon: IconCheck },
  CANCELLED: { label: 'Cancelled', variant: 'destructive' as const, icon: IconClock },
}

const paymentStatusConfig = {
  PENDING: { label: 'Pending', variant: 'secondary' as const },
  PAID: { label: 'Paid', variant: 'default' as const },
  FAILED: { label: 'Failed', variant: 'destructive' as const },
  REFUNDED: { label: 'Refunded', variant: 'outline' as const },
}

export const columns: ColumnDef<OrderWithDetails>[] = [
  {
    accessorKey: 'orderNumber',
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Order" />
    ),
    cell: ({ row }) => {
      const order = row.original
      return (
        <div className="flex flex-col">
          <span className="font-medium">#{order.orderNumber}</span>
          <span className="text-xs text-muted-foreground">
            {new Date(order.createdAt).toLocaleDateString('en-ZA', {
              day: '2-digit',
              month: 'short',
              year: 'numeric'
            })}
          </span>
        </div>
      )
    },
    enableSorting: true,
    enableHiding: false,
  },
  {
    accessorKey: 'items',
    header: 'Items',
    cell: ({ row }) => {
      const order = row.original
      const itemCount = order.items?.length || 0
      const firstItem = order.items?.[0]
      
      return (
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-muted rounded-lg flex items-center justify-center overflow-hidden">
            {firstItem?.product?.images?.[0] ? (
              <img
                src={firstItem.product.images[0].url}
                alt={firstItem.product.name}
                className="w-full h-full object-cover"
              />
            ) : (
              <IconPackage className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
          <div className="flex flex-col">
            <span className="font-medium text-sm">
              {itemCount} item{itemCount !== 1 ? 's' : ''}
            </span>
            {firstItem && (
              <span className="text-xs text-muted-foreground truncate max-w-[150px]">
                {firstItem.product.name}
                {itemCount > 1 && ` +${itemCount - 1} more`}
              </span>
            )}
          </div>
        </div>
      )
    },
    enableSorting: false,
  },
  {
    accessorKey: 'status',
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => {
      const status = row.getValue('status') as keyof typeof statusConfig
      const config = statusConfig[status]
      const Icon = config.icon
      
      return (
        <Badge variant={config.variant}>
          <Icon className="mr-1 h-3 w-3" />
          {config.label}
        </Badge>
      )
    },
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id))
    },
    enableSorting: true,
  },
  {
    accessorKey: 'paymentStatus',
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Payment" />
    ),
    cell: ({ row }) => {
      const paymentStatus = row.getValue('paymentStatus') as keyof typeof paymentStatusConfig
      const config = paymentStatusConfig[paymentStatus]
      
      return (
        <div className="flex items-center space-x-2">
          <IconCreditCard className="h-3 w-3 text-muted-foreground" />
          <Badge variant={config.variant} className="text-xs">
            {config.label}
          </Badge>
        </div>
      )
    },
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id))
    },
    enableSorting: true,
  },
  {
    accessorKey: 'shippingAddress',
    header: 'Shipping',
    cell: ({ row }) => {
      const order = row.original
      const address = order.shippingAddress
      
      if (!address) {
        return <span className="text-muted-foreground text-sm">No address</span>
      }
      
      return (
        <div className="flex items-center space-x-2">
          <IconMapPin className="h-3 w-3 text-muted-foreground" />
          <span className="text-sm">
            {address.city}, {address.province}
          </span>
        </div>
      )
    },
    enableSorting: false,
  },
  {
    accessorKey: 'totalAmount',
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Total" />
    ),
    cell: ({ row }) => {
      const amount = parseFloat(row.getValue('totalAmount'))
      return (
        <div className="font-medium">
          {formatPrice(amount)}
        </div>
      )
    },
    enableSorting: true,
  },
  {
    id: 'actions',
    header: 'Actions',
    cell: ({ row }) => {
      const order = row.original
      
      return (
        <Button variant="ghost" size="sm" asChild>
          <Link href={`/orders/${order.id}`}>
            <IconEye className="mr-2 h-4 w-4" />
            View Details
          </Link>
        </Button>
      )
    },
    enableSorting: false,
    enableHiding: false,
  },
]
