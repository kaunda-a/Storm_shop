'use client'

import { useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { useSession } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import {
  IconHeart,
  IconShoppingCart,
  IconStar,
  IconEye,
  IconGitCompare,
  IconLogin
} from '@tabler/icons-react'
import { useCartStore } from '@/lib/cart-store'
import { formatPrice } from '@/lib/format'
import type { ProductCardProps } from '../types'

export function ProductCard({
  product,
  showQuickView = true,
  showCompare = true,
  priority = false
}: ProductCardProps) {
  const [isWishlisted, setIsWishlisted] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const { data: session } = useSession()
  const router = useRouter()
  const { addItem } = useCartStore()

  const primaryImage = product.images.find(img => img.isPrimary) || product.images[0]
  const cheapestVariant = product.variants.reduce((prev, current) => 
    Number(prev.price) < Number(current.price) ? prev : current
  )
  
  const hasDiscount = cheapestVariant?.comparePrice && 
    Number(cheapestVariant.comparePrice) > Number(cheapestVariant.price)
  
  const discountPercentage = hasDiscount 
    ? Math.round(((Number(cheapestVariant.comparePrice) - Number(cheapestVariant.price)) / Number(cheapestVariant.comparePrice)) * 100)
    : 0

  const handleAddToCart = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()

    // Check if user is authenticated
    if (!session) {
      router.push(`/auth/customer-sign-in?callbackUrl=${encodeURIComponent(window.location.href)}`)
      return
    }

    if (!cheapestVariant || cheapestVariant.stock === 0) return

    setIsLoading(true)
    try {
      addItem({
        productId: product.id,
        variantId: cheapestVariant.id,
        name: product.name,
        price: Number(cheapestVariant.price),
        image: primaryImage?.url || '/placeholder-product.jpg',
        size: cheapestVariant.size,
        color: cheapestVariant.color,
        quantity: 1,
        sku: cheapestVariant.sku,
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleWishlist = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsWishlisted(!isWishlisted)
  }

  const handleQuickView = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    // TODO: Implement quick view modal
    console.log('Quick view:', product.id)
  }

  const inStock = product.variants.some(v => v.stock > 0)

  return (
    <Card className="group overflow-hidden border-0 shadow-sm hover:shadow-xl transition-all duration-300 transform hover:-translate-y-1">
      <CardContent className="p-0">
        <Link href={`/products/${product.id}`}>
          {/* Product Image */}
          <div className="relative aspect-square overflow-hidden bg-gray-50">
            {primaryImage ? (
              <Image
                src={primaryImage.url}
                alt={primaryImage.altText || product.name}
                fill
                className="object-cover group-hover:scale-105 transition-transform duration-300"
                priority={priority}
                sizes="(min-width: 1024px) 25vw, (min-width: 768px) 33vw, (min-width: 640px) 50vw, 100vw"
              />
            ) : (
              <div className="w-full h-full flex items-center justify-center">
                <div className="text-center space-y-2">
                  <div className="w-20 h-20 mx-auto bg-primary/10 rounded-full flex items-center justify-center">
                    <span className="text-lg font-bold text-primary">IMG</span>
                  </div>
                  <p className="text-xs text-muted-foreground">No Image</p>
                </div>
              </div>
            )}
            
            {/* Badges */}
            <div className="absolute top-3 left-3 flex flex-col gap-2">
              {product.isFeatured && (
                <Badge variant="default" className="text-xs">
                  Featured
                </Badge>
              )}
              {discountPercentage > 0 && (
                <Badge variant="destructive" className="text-xs">
                  -{discountPercentage}%
                </Badge>
              )}
              {!inStock && (
                <Badge variant="secondary" className="text-xs">
                  Out of Stock
                </Badge>
              )}
            </div>

            {/* Action buttons */}
            <div className="absolute top-3 right-3 flex flex-col gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <Button
                variant="secondary"
                size="icon"
                className="h-8 w-8 rounded-full bg-white/90 hover:bg-white"
                onClick={handleWishlist}
              >
                <IconHeart 
                  className={`h-4 w-4 ${isWishlisted ? 'fill-red-500 text-red-500' : ''}`} 
                />
              </Button>
              
              {showQuickView && (
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-8 w-8 rounded-full bg-white/90 hover:bg-white"
                  onClick={handleQuickView}
                >
                  <IconEye className="h-4 w-4" />
                </Button>
              )}
              
              {showCompare && (
                <Button
                  variant="secondary"
                  size="icon"
                  className="h-8 w-8 rounded-full bg-white/90 hover:bg-white"
                >
                  <IconGitCompare className="h-4 w-4" />
                </Button>
              )}
            </div>

            {/* Quick add to cart */}
            <div className="absolute bottom-3 left-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
              <Button
                size="sm"
                className="w-full"
                onClick={handleAddToCart}
                disabled={(!inStock && !!session) || isLoading}
              >
                {!session ? (
                  <>
                    <IconLogin className="mr-2 h-4 w-4" />
                    Sign In to Buy
                  </>
                ) : !inStock ? (
                  <>
                    <IconShoppingCart className="mr-2 h-4 w-4" />
                    Out of Stock
                  </>
                ) : isLoading ? (
                  <>
                    <IconShoppingCart className="mr-2 h-4 w-4" />
                    Adding...
                  </>
                ) : (
                  <>
                    <IconShoppingCart className="mr-2 h-4 w-4" />
                    Add to Cart
                  </>
                )}
              </Button>
            </div>
          </div>
        </Link>

        {/* Product Info */}
        <div className="p-4 space-y-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <p className="text-sm text-muted-foreground truncate">
                {product.brand.name}
              </p>
              <Link href={`/products/${product.id}`}>
                <h3 className="font-medium text-sm leading-tight line-clamp-2 hover:text-primary transition-colors">
                  {product.name}
                </h3>
              </Link>
            </div>
          </div>

          {/* Rating */}
          {product._count.reviews > 0 && (
            <div className="flex items-center gap-1">
              <div className="flex items-center">
                {[...Array(5)].map((_, i) => (
                  <IconStar
                    key={i}
                    className={`h-3 w-3 ${
                      i < 4 ? 'fill-yellow-400 text-yellow-400' : 'text-gray-300'
                    }`}
                  />
                ))}
              </div>
              <span className="text-xs text-muted-foreground">
                ({product._count.reviews})
              </span>
            </div>
          )}

          {/* Price */}
          <div className="flex items-center gap-2">
            <span className="font-semibold text-lg">
              {formatPrice(Number(cheapestVariant.price))}
            </span>
            {hasDiscount && (
              <span className="text-sm text-muted-foreground line-through">
                {formatPrice(Number(cheapestVariant.comparePrice))}
              </span>
            )}
          </div>

          {/* Category */}
          <p className="text-xs text-muted-foreground">
            {product.category.name}
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
