import { Suspense } from 'react'
import { ProductService, type ProductFilters, type ProductSort } from '@/lib/services/products'
import { ProductGrid } from './product-grid'
import { ProductPagination } from './product-pagination'
import { ProductSort as ProductSortComponent } from './product-sort'
import { Skeleton } from '@/components/ui/skeleton'

interface ProductCatalogProps {
  searchParams: {
    page?: string
    sort?: string
    category?: string
    brand?: string
    minPrice?: string
    maxPrice?: string
    search?: string
    size?: string
    color?: string
  }
  showSort?: boolean
  showPagination?: boolean
  limit?: number
}

function ProductCatalogSkeleton() {
  return (
    <div className="space-y-6">
      {/* Sort skeleton */}
      <div className="flex justify-between items-center">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-10 w-48" />
      </div>
      
      {/* Grid skeleton */}
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
    </div>
  )
}

async function ProductCatalogContent({ 
  searchParams, 
  showSort = true, 
  showPagination = true,
  limit = 12 
}: ProductCatalogProps) {
  const page = parseInt(searchParams.page || '1')
  const sortParam = searchParams.sort || 'newest'

  // Build filters
  const filters: ProductFilters = {
    isActive: true,
    status: 'ACTIVE',
  }

  if (searchParams.search) {
    filters.search = searchParams.search
  }

  if (searchParams.category) {
    filters.categoryId = searchParams.category
  }

  if (searchParams.brand) {
    filters.brandId = searchParams.brand
  }

  if (searchParams.minPrice) {
    filters.minPrice = parseFloat(searchParams.minPrice)
  }

  if (searchParams.maxPrice) {
    filters.maxPrice = parseFloat(searchParams.maxPrice)
  }

  // Note: size and color filtering would need to be handled at the variant level
  // These are not part of the ProductFilters type

  // Build sort
  const sort: ProductSort = (() => {
    switch (sortParam) {
      case 'oldest':
        return { field: 'createdAt', direction: 'asc' }
      case 'price-low-high':
        return { field: 'price', direction: 'asc' }
      case 'price-high-low':
        return { field: 'price', direction: 'desc' }
      case 'name-a-z':
        return { field: 'name', direction: 'asc' }
      case 'name-z-a':
        return { field: 'name', direction: 'desc' }
      case 'featured':
        return { field: 'createdAt', direction: 'desc' } // fallback since isFeatured not in ProductSort
      case 'rating':
        return { field: 'createdAt', direction: 'desc' } // fallback since rating not in ProductSort
      case 'newest':
      default:
        return { field: 'createdAt', direction: 'desc' }
    }
  })()

  try {
    const { products, pagination } = await ProductService.getProducts({
      filters,
      sort,
      page,
      limit,
    })

    return (
      <div className="space-y-6">
        {/* Results Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="text-sm text-muted-foreground">
            {pagination.total === 0 ? (
              'No products found'
            ) : (
              <>
                Showing {((page - 1) * limit) + 1}-{Math.min(page * limit, pagination.total)} of {pagination.total} products
                {searchParams.search && (
                  <span> for "{searchParams.search}"</span>
                )}
              </>
            )}
          </div>
          
          {showSort && products.length > 0 && (
            <ProductSortComponent currentSort={sortParam} />
          )}
        </div>

        {/* Products Grid */}
        <ProductGrid products={products} />

        {/* Pagination */}
        {showPagination && pagination.pages > 1 && (
          <ProductPagination 
            currentPage={page}
            totalPages={pagination.pages}
            totalItems={pagination.total}
          />
        )}
      </div>
    )
  } catch (error) {
    console.error('Error loading products:', error)
    return (
      <div className="text-center py-12">
        <h3 className="text-lg font-semibold mb-2">Something went wrong</h3>
        <p className="text-muted-foreground">
          We couldn't load the products. Please try again later.
        </p>
      </div>
    )
  }
}

export function ProductCatalog(props: ProductCatalogProps) {
  return (
    <Suspense fallback={<ProductCatalogSkeleton />}>
      <ProductCatalogContent {...props} />
    </Suspense>
  )
}
