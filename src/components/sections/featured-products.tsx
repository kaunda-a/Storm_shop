import { ProductGrid } from '@/features/product/components/product-grid'
import { ProductService } from '@/lib/services/products'

export async function FeaturedProducts() {
  try {
    const { products } = await ProductService.getProducts({
      page: 1,
      limit: 8,
      filters: { isFeatured: true }
    })

    if (!products.length) {
      return null
    }

    return (
      <section className="py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Featured Products
            </h2>
            <p className="text-lg text-gray-600 max-w-2xl mx-auto">
              Discover our handpicked selection of premium footwear
            </p>
          </div>
          
          <ProductGrid 
            products={products}
            showQuickView={true}
            showCompare={true}
          />
        </div>
      </section>
    )
  } catch (error) {
    console.error('Error loading featured products:', error)
    return null
  }
}
