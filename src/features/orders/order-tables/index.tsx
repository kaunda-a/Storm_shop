'use client'

import { DataTable } from '@/components/ui/table/data-table'
import { DataTableToolbar } from '@/components/ui/table/data-table-toolbar'
import { OrderEmptyState } from './order-empty-state'
import { OrderWithDetails } from '@/lib/services'
import { useDataTable } from '@/hooks/use-data-table'
import { ColumnDef } from '@tanstack/react-table'
import { parseAsInteger, useQueryState } from 'nuqs'

interface OrderTableProps {
  data: OrderWithDetails[]
  totalItems: number
  columns: ColumnDef<OrderWithDetails>[]
}

export function OrderTable({ data, totalItems, columns }: OrderTableProps) {
  const [pageSize] = useQueryState('perPage', parseAsInteger.withDefault(10))
  const pageCount = Math.ceil(totalItems / pageSize)

  const { table } = useDataTable({
    data,
    columns,
    pageCount,
    shallow: false,
    debounceMs: 500
  })

  // Show empty state if no data
  if (data.length === 0 && totalItems === 0) {
    return <OrderEmptyState />;
  }

  return (
    <DataTable table={table}>
      <DataTableToolbar table={table} />
    </DataTable>
  )
}
