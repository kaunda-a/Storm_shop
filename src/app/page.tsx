import Header from '@/components/layout/header';
import { StoreFooter } from '@/components/layout/store-footer';
import { MarqueeContainer } from '@/components/marquee-container';
import { BillboardContainer } from '@/components/layout/billboard-container';
import { FeaturedProducts } from '@/components/sections/featured-products';

export default function HomePage() {
  return (
    <>
      <Header />
      <main className="flex-1">
        <MarqueeContainer />
        {/* Hero Billboard Carousel */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <BillboardContainer
            position="HEADER"
            className="min-h-[400px] md:min-h-[500px]"
          />
        </div>
        <FeaturedProducts />
        {/* Footer Billboard Carousel */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <BillboardContainer
            position="FOOTER"
            className="min-h-[300px]"
          />
        </div>
      </main>
      <StoreFooter />
    </>
  );
}
