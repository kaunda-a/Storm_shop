import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import Header from '@/components/layout/header';
import { StoreFooter } from '@/components/layout/store-footer';
import { ProductService } from '@/lib/services/products';
import { ProductDetailView } from '@/features/product/components/product-detail-view';
import { RelatedProducts } from '@/features/product/components/related-products';
import { ProductReviews } from '@/features/product/components/product-reviews';
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb';

export async function generateMetadata(props: {
  params: Promise<{ productId: string }>;
}): Promise<Metadata> {
  const params = await props.params;

  try {
    const product = await ProductService.getProductById(params.productId);
    
    if (!product) return notFound();

    const primaryImage = product.images.find(img => img.isPrimary) || product.images[0];

    return {
      title: `${product.name} - ${product.brand.name} | Mzansi Footwear`,
      description: product.shortDescription || product.description || `${product.name} by ${product.brand.name}. Premium South African footwear.`,
      keywords: [product.name, product.brand.name, product.category.name, ...product.tags].join(', '),
      robots: {
        index: product.isActive && product.status === 'ACTIVE',
        follow: product.isActive && product.status === 'ACTIVE',
      },
      openGraph: primaryImage ? {
        images: [
          {
            url: primaryImage.url,
            alt: primaryImage.altText || product.name,
          }
        ]
      } : undefined
    };
  } catch (error) {
    return notFound();
  }
}

export default async function ProductPage(props: { params: Promise<{ productId: string }> }) {
  const params = await props.params;

  try {
    const product = await ProductService.getProductById(params.productId);
    
    if (!product) return notFound();

    const primaryImage = product.images.find(img => img.isPrimary) || product.images[0];
    const minPrice = Math.min(...product.variants.map(v => Number(v.price)));
    const maxPrice = Math.max(...product.variants.map(v => Number(v.price)));
    const inStock = product.variants.some(v => v.stock > 0);

    const productJsonLd = {
      '@context': 'https://schema.org',
      '@type': 'Product',
      name: product.name,
      description: product.description,
      brand: {
        '@type': 'Brand',
        name: product.brand.name
      },
      category: product.category.name,
      image: primaryImage?.url,
      sku: product.sku,
      offers: {
        '@type': 'AggregateOffer',
        availability: inStock ? 'https://schema.org/InStock' : 'https://schema.org/OutOfStock',
        priceCurrency: 'ZAR',
        lowPrice: minPrice,
        highPrice: maxPrice
      }
    };

    return (
      <>
        <Header />
        <main className="flex-1">
          <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{
              __html: JSON.stringify(productJsonLd)
            }}
          />
          
          {/* Breadcrumbs */}
          <div className="bg-gray-50 border-b">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
              <Breadcrumb>
                <BreadcrumbList>
                  <BreadcrumbItem>
                    <BreadcrumbLink href="/">Home</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbLink href="/products">Products</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbLink href={`/categories/${product.category.slug}`}>
                      {product.category.name}
                    </BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                  <BreadcrumbItem>
                    <BreadcrumbPage>{product.name}</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
          </div>

          {/* Product Detail */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Suspense fallback={<div className="h-96 bg-gray-200 rounded animate-pulse" />}>
              <ProductDetailView product={product} />
            </Suspense>
          </div>

          {/* Product Reviews */}
          <div className="bg-gray-50">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
              <Suspense fallback={<div className="h-64 bg-gray-200 rounded animate-pulse" />}>
                <ProductReviews productId={product.id} />
              </Suspense>
            </div>
          </div>

          {/* Related Products */}
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
            <Suspense fallback={<div className="h-64 bg-gray-200 rounded animate-pulse" />}>
              <RelatedProducts 
                productId={product.id} 
                categoryId={product.categoryId}
                brandId={product.brandId}
              />
            </Suspense>
          </div>
        </main>
        <StoreFooter />
      </>
    );
  } catch (error) {
    console.error('Error loading product:', error);
    return notFound();
  }
}
