import { Suspense } from 'react';
import Header from '@/components/layout/header';
import { StoreFooter } from '@/components/layout/store-footer';
import { ProductCatalog } from '@/features/product/components/product-catalog';
import { ProductFilters } from '@/features/product/components/product-filters';
import { ProductSort } from '@/features/product/components/product-sort';
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb';

interface ProductsPageProps {
  searchParams: Promise<{
    page?: string;
    sort?: string;
    category?: string;
    brand?: string;
    minPrice?: string;
    maxPrice?: string;
    search?: string;
    size?: string;
    color?: string;
  }>;
}

export default async function ProductsPage({ searchParams }: ProductsPageProps) {
  const params = await searchParams;
  
  return (
    <>
      <Header />
      <main className="flex-1">
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
                  <BreadcrumbPage>Products</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </div>

        {/* Page Header */}
        <div className="bg-white border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h1 className="text-3xl font-bold text-gray-900">All Products</h1>
                <p className="mt-2 text-lg text-gray-600">
                  Discover our complete collection of premium footwear
                </p>
              </div>
              
              {/* Sort Controls - Desktop */}
              <div className="mt-6 lg:mt-0">
                <Suspense fallback={<div className="h-10 w-48 bg-gray-200 rounded animate-pulse" />}>
                  <ProductSort />
                </Suspense>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="lg:grid lg:grid-cols-4 lg:gap-8">
            {/* Filters Sidebar */}
            <div className="hidden lg:block">
              <div className="sticky top-24">
                <Suspense fallback={<div className="h-96 bg-gray-200 rounded animate-pulse" />}>
                  <ProductFilters />
                </Suspense>
              </div>
            </div>

            {/* Products Grid */}
            <div className="lg:col-span-3">
              <Suspense fallback={<div className="h-96 bg-gray-200 rounded animate-pulse" />}>
                <ProductCatalog searchParams={params} />
              </Suspense>
            </div>
          </div>
        </div>
      </main>
      <StoreFooter />
    </>
  );
}
