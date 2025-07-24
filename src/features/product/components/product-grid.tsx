'use client'

import { ProductCard } from './product-card'
import { Skeleton } from '@/components/ui/skeleton'
import { IconShoppingCart } from '@tabler/icons-react'
import type { ProductGridProps } from '../types'

function ProductGridSkeleton() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {[...Array(8)].map((_, i) => (
        <div key={i} className="space-y-4">
          <Skeleton className="aspect-square rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-3 w-1/2" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/3" />
            <Skeleton className="h-6 w-1/2" />
          </div>
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="text-center py-12">
      <div className="w-24 h-24 mx-auto bg-muted rounded-full flex items-center justify-center mb-4">
        <IconShoppingCart className="h-12 w-12 text-muted-foreground" />
      </div>
      <h3 className="text-lg font-semibold mb-2">No products found</h3>
      <p className="text-muted-foreground max-w-md mx-auto">
        Try adjusting your search or filter criteria to find what you're looking for.
      </p>
    </div>
  )
}

export function ProductGrid({ 
  products, 
  loading = false, 
  className = '',
  showQuickView = true,
  showCompare = true
}: ProductGridProps) {
  if (loading) {
    return <ProductGridSkeleton />
  }

  if (!products.length) {
    return <EmptyState />
  }

  return (
    <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 ${className}`}>
      {products.map((product, index) => (
        <ProductCard 
          key={product.id} 
          product={product}
          showQuickView={showQuickView}
          showCompare={showCompare}
          priority={index < 4} // Prioritize first 4 images for LCP
        />
      ))}
    </div>
  )
}
