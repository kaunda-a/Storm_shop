import { ProductService } from '@/lib/services/products'
import { ProductGrid } from './product-grid'
import type { RelatedProductsProps } from '../types'

export async function RelatedProducts({ 
  productId, 
  categoryId, 
  brandId, 
  limit = 8 
}: RelatedProductsProps) {
  try {
    // Strategy 1: Get products from the same category
    let { products } = await ProductService.getProducts({
      filters: {
        categoryId,
        isActive: true,
        status: 'ACTIVE',
      },
      limit: limit + 1, // Get one extra to filter out current product
      sort: { field: 'createdAt', direction: 'desc' }
    })

    // Filter out the current product
    products = products.filter(p => p.id !== productId)

    // Strategy 2: If we don't have enough products from the same category, 
    // get from the same brand
    if (products.length < 4) {
      const { products: brandProducts } = await ProductService.getProducts({
        filters: {
          brandId,
          isActive: true,
          status: 'ACTIVE',
        },
        limit: limit - products.length + 1,
        sort: { field: 'createdAt', direction: 'desc' }
      })

      // Add brand products that aren't already included and aren't the current product
      const additionalProducts = brandProducts.filter(
        p => p.id !== productId && !products.some(existing => existing.id === p.id)
      )
      
      products = [...products, ...additionalProducts]
    }

    // Strategy 3: If we still don't have enough, get featured products
    if (products.length < 4) {
      const { products: featuredProducts } = await ProductService.getProducts({
        filters: {
          isFeatured: true,
          isActive: true,
          status: 'ACTIVE',
        },
        limit: limit - products.length + 1,
        sort: { field: 'createdAt', direction: 'desc' }
      })

      // Add featured products that aren't already included and aren't the current product
      const additionalProducts = featuredProducts.filter(
        p => p.id !== productId && !products.some(existing => existing.id === p.id)
      )
      
      products = [...products, ...additionalProducts]
    }

    // Strategy 4: If we still don't have enough, get any recent products
    if (products.length < 4) {
      const { products: recentProducts } = await ProductService.getProducts({
        filters: {
          isActive: true,
          status: 'ACTIVE',
        },
        limit: limit - products.length + 1,
        sort: { field: 'createdAt', direction: 'desc' }
      })

      // Add recent products that aren't already included and aren't the current product
      const additionalProducts = recentProducts.filter(
        p => p.id !== productId && !products.some(existing => existing.id === p.id)
      )
      
      products = [...products, ...additionalProducts]
    }

    // Limit to the requested number of products
    products = products.slice(0, limit)

    if (!products.length) {
      return null
    }

    return (
      <section className="space-y-6">
        <div className="text-center space-y-2">
          <h2 className="text-2xl font-bold tracking-tight">
            You Might Also Like
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Discover more products that complement your style
          </p>
        </div>
        
        <ProductGrid 
          products={products} 
          showQuickView={true}
          showCompare={false}
          className="grid-cols-1 sm:grid-cols-2 lg:grid-cols-4"
        />
      </section>
    )
  } catch (error) {
    console.error('Error loading related products:', error)
    return null
  }
}
