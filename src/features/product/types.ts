import type { ProductWithDetails } from '@/lib/services/products'

export interface ProductGridProps {
  products: ProductWithDetails[]
  loading?: boolean
  className?: string
  showQuickView?: boolean
  showCompare?: boolean
}

export interface ProductCardProps {
  product: ProductWithDetails
  showQuickView?: boolean
  showCompare?: boolean
  priority?: boolean
}

export interface ProductFiltersProps {
  categories?: Array<{ id: string; name: string; slug: string }>
  brands?: Array<{ id: string; name: string; slug: string }>
  priceRange?: { min: number; max: number }
  onFiltersChange?: (filters: any) => void
}

export interface ProductSortProps {
  currentSort?: string
  onSortChange?: (sort: string) => void
}

export interface ProductPaginationProps {
  currentPage: number
  totalPages: number
  totalItems: number
  onPageChange?: (page: number) => void
}

export interface ProductSearchProps {
  placeholder?: string
  onSearch?: (query: string) => void
  initialValue?: string
}

export interface RelatedProductsProps {
  productId: string
  categoryId: string
  brandId: string
  limit?: number
}

export interface ProductGalleryProps {
  images: Array<{
    id: string
    url: string
    altText: string | null
    isPrimary: boolean
  }>
  productName: string
}

export interface VariantSelectorProps {
  variants: Array<{
    id: string
    size: string
    color: string
    stock: number
    price: number
    comparePrice?: number | null
  }>
  selectedVariant?: string
  onVariantChange?: (variantId: string) => void
}

export interface ProductReviewsProps {
  productId: string
  averageRating?: number
  totalReviews?: number
}
