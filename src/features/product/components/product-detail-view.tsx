'use client'

import { useState } from 'react'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  IconHeart,
  IconShoppingCart,
  IconStar,
  IconTruck,
  IconShield,
  IconRefresh,
  IconMinus,
  IconPlus,
  IconShare,
  IconGitCompare,
  IconLogin
} from '@tabler/icons-react'
import { useCartStore } from '@/lib/cart-store'
import { ProductGallery } from './product-gallery'
import { VariantSelector } from './variant-selector'
import type { ProductWithDetails } from '@/lib/services/products'

interface ProductDetailViewProps {
  product: ProductWithDetails
}

export function ProductDetailView({ product }: ProductDetailViewProps) {
  const [selectedVariantId, setSelectedVariantId] = useState(product.variants[0]?.id)
  const [quantity, setQuantity] = useState(1)
  const [isWishlisted, setIsWishlisted] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const { data: session } = useSession()
  const router = useRouter()
  const { addItem } = useCartStore()

  const selectedVariant = product.variants.find(v => v.id === selectedVariantId) || product.variants[0]
  const primaryImage = product.images.find(img => img.isPrimary) || product.images[0]

  const handleAddToCart = async () => {
    // Check if user is authenticated
    if (!session) {
      router.push(`/auth/customer-sign-in?callbackUrl=${encodeURIComponent(window.location.href)}`)
      return
    }

    if (!selectedVariant || selectedVariant.stock === 0) return

    setIsLoading(true)
    try {
      addItem({
        productId: product.id,
        variantId: selectedVariant.id,
        name: product.name,
        price: Number(selectedVariant.price),
        image: primaryImage?.url || '/placeholder-product.jpg',
        size: selectedVariant.size,
        color: selectedVariant.color,
        quantity,
        sku: selectedVariant.sku,
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleQuantityChange = (newQuantity: number) => {
    if (newQuantity >= 1 && newQuantity <= (selectedVariant?.stock || 0)) {
      setQuantity(newQuantity)
    }
  }

  const handleWishlist = () => {
    setIsWishlisted(!isWishlisted)
  }

  const handleShare = () => {
    if (navigator.share) {
      navigator.share({
        title: product.name,
        text: product.description || '',
        url: window.location.href,
      })
    } else {
      // Fallback: copy to clipboard
      navigator.clipboard.writeText(window.location.href)
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12">
      {/* Product Images */}
      <div className="space-y-4">
        <ProductGallery images={product.images} productName={product.name} />
      </div>

      {/* Product Info */}
      <div className="space-y-6">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant="outline">{product.brand.name}</Badge>
            {product.isFeatured && (
              <Badge variant="default">Featured</Badge>
            )}
          </div>
          <h1 className="text-3xl font-bold tracking-tight">{product.name}</h1>
          
          {/* Rating */}
          {product._count.reviews > 0 && (
            <div className="flex items-center gap-2">
              <div className="flex items-center">
                {[...Array(5)].map((_, i) => (
                  <IconStar
                    key={i}
                    className={`h-4 w-4 ${
                      i < 4 ? 'fill-yellow-400 text-yellow-400' : 'text-gray-300'
                    }`}
                  />
                ))}
              </div>
              <span className="text-sm text-muted-foreground">
                4.0 ({product._count.reviews} reviews)
              </span>
            </div>
          )}
        </div>

        {/* Variant Selection */}
        <VariantSelector
          variants={product.variants.map(v => ({
            id: v.id,
            size: v.size,
            color: v.color,
            stock: v.stock,
            price: Number(v.price),
            comparePrice: v.comparePrice ? Number(v.comparePrice) : null,
          }))}
          selectedVariant={selectedVariantId}
          onVariantChange={setSelectedVariantId}
        />

        <Separator />

        {/* Quantity and Add to Cart */}
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <span className="font-medium">Quantity:</span>
            <div className="flex items-center border rounded-md">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => handleQuantityChange(quantity - 1)}
                disabled={quantity <= 1}
              >
                <IconMinus className="h-4 w-4" />
              </Button>
              <span className="px-4 py-2 min-w-[3rem] text-center">{quantity}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => handleQuantityChange(quantity + 1)}
                disabled={quantity >= (selectedVariant?.stock || 0)}
              >
                <IconPlus className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="flex gap-3">
            <Button
              size="lg"
              className="flex-1"
              onClick={handleAddToCart}
              disabled={(selectedVariant?.stock === 0 && !!session) || isLoading}
            >
              {!session ? (
                <>
                  <IconLogin className="mr-2 h-5 w-5" />
                  Sign In to Purchase
                </>
              ) : selectedVariant?.stock === 0 ? (
                <>
                  <IconShoppingCart className="mr-2 h-5 w-5" />
                  Out of Stock
                </>
              ) : isLoading ? (
                <>
                  <IconShoppingCart className="mr-2 h-5 w-5" />
                  Adding to Cart...
                </>
              ) : (
                <>
                  <IconShoppingCart className="mr-2 h-5 w-5" />
                  Add to Cart
                </>
              )}
            </Button>
            <Button
              variant="outline"
              size="lg"
              onClick={handleWishlist}
            >
              <IconHeart
                className={`h-5 w-5 ${isWishlisted ? 'fill-red-500 text-red-500' : ''}`}
              />
            </Button>
            <Button variant="outline" size="lg" onClick={handleShare}>
              <IconShare className="h-5 w-5" />
            </Button>
          </div>
        </div>

        <Separator />

        {/* Product Details Tabs */}
        <Tabs defaultValue="description" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="description">Description</TabsTrigger>
            <TabsTrigger value="specifications">Specifications</TabsTrigger>
            <TabsTrigger value="shipping">Shipping</TabsTrigger>
          </TabsList>
          
          <TabsContent value="description" className="space-y-4">
            <div className="prose prose-sm max-w-none">
              <p>{product.description || 'No description available.'}</p>
            </div>
          </TabsContent>
          
          <TabsContent value="specifications" className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="font-medium">SKU:</span>
                <span className="ml-2 text-muted-foreground">{product.sku}</span>
              </div>
              <div>
                <span className="font-medium">Category:</span>
                <span className="ml-2 text-muted-foreground">{product.category.name}</span>
              </div>
              <div>
                <span className="font-medium">Brand:</span>
                <span className="ml-2 text-muted-foreground">{product.brand.name}</span>
              </div>
              {selectedVariant && (
                <>
                  <div>
                    <span className="font-medium">Weight:</span>
                    <span className="ml-2 text-muted-foreground">
                      {selectedVariant.weight ? `${selectedVariant.weight}g` : 'N/A'}
                    </span>
                  </div>
                </>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="shipping" className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <IconTruck className="h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Free Shipping</p>
                  <p className="text-sm text-muted-foreground">On orders over R500</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <IconShield className="h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Secure Payment</p>
                  <p className="text-sm text-muted-foreground">Your payment information is safe</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <IconRefresh className="h-5 w-5 text-primary" />
                <div>
                  <p className="font-medium">Easy Returns</p>
                  <p className="text-sm text-muted-foreground">30-day return policy</p>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
