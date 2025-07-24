'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { formatPrice } from '@/lib/format'
import type { VariantSelectorProps } from '../types'

export function VariantSelector({ 
  variants, 
  selectedVariant, 
  onVariantChange 
}: VariantSelectorProps) {
  const [selectedVariantId, setSelectedVariantId] = useState(selectedVariant || variants[0]?.id)

  useEffect(() => {
    if (selectedVariant) {
      setSelectedVariantId(selectedVariant)
    }
  }, [selectedVariant])

  const handleVariantChange = (variantId: string) => {
    setSelectedVariantId(variantId)
    onVariantChange?.(variantId)
  }

  if (!variants.length) {
    return (
      <div className="text-center py-4">
        <p className="text-muted-foreground">No variants available</p>
      </div>
    )
  }

  // Group variants by color and size
  const colors = Array.from(new Set(variants.map(v => v.color)))
  const sizes = Array.from(new Set(variants.map(v => v.size)))

  const selectedVariantData = variants.find(v => v.id === selectedVariantId)
  const selectedColor = selectedVariantData?.color
  const selectedSize = selectedVariantData?.size

  // Get available sizes for selected color
  const availableSizesForColor = selectedColor 
    ? variants.filter(v => v.color === selectedColor).map(v => v.size)
    : []

  // Get available colors for selected size
  const availableColorsForSize = selectedSize
    ? variants.filter(v => v.size === selectedSize).map(v => v.color)
    : []

  const handleColorChange = (color: string) => {
    // Find a variant with this color, preferring the current size if available
    const variantWithColor = variants.find(v => 
      v.color === color && (selectedSize ? v.size === selectedSize : true)
    ) || variants.find(v => v.color === color)
    
    if (variantWithColor) {
      handleVariantChange(variantWithColor.id)
    }
  }

  const handleSizeChange = (size: string) => {
    // Find a variant with this size, preferring the current color if available
    const variantWithSize = variants.find(v => 
      v.size === size && (selectedColor ? v.color === selectedColor : true)
    ) || variants.find(v => v.size === size)
    
    if (variantWithSize) {
      handleVariantChange(variantWithSize.id)
    }
  }

  return (
    <div className="space-y-6">
      {/* Price */}
      {selectedVariantData && (
        <div className="flex items-center gap-3">
          <span className="text-2xl font-bold">
            {formatPrice(selectedVariantData.price)}
          </span>
          {selectedVariantData.comparePrice && selectedVariantData.comparePrice > selectedVariantData.price && (
            <span className="text-lg text-muted-foreground line-through">
              {formatPrice(selectedVariantData.comparePrice)}
            </span>
          )}
          {selectedVariantData.comparePrice && selectedVariantData.comparePrice > selectedVariantData.price && (
            <Badge variant="destructive">
              Save {formatPrice(selectedVariantData.comparePrice - selectedVariantData.price)}
            </Badge>
          )}
        </div>
      )}

      {/* Color Selection */}
      {colors.length > 1 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="font-medium">Color:</span>
            <span className="text-muted-foreground">{selectedColor}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {colors.map((color) => {
              const isSelected = color === selectedColor
              const isAvailable = !selectedSize || availableColorsForSize.includes(color)
              const variantForColor = variants.find(v => v.color === color)
              
              return (
                <Button
                  key={color}
                  variant={isSelected ? "default" : "outline"}
                  size="sm"
                  className={`${!isAvailable ? 'opacity-50 cursor-not-allowed' : ''}`}
                  onClick={() => isAvailable && handleColorChange(color)}
                  disabled={!isAvailable}
                >
                  {color}
                  {variantForColor && variantForColor.stock === 0 && (
                    <span className="ml-1 text-xs">(Out of stock)</span>
                  )}
                </Button>
              )
            })}
          </div>
        </div>
      )}

      {/* Size Selection */}
      {sizes.length > 1 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="font-medium">Size:</span>
            <span className="text-muted-foreground">{selectedSize}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {sizes.map((size) => {
              const isSelected = size === selectedSize
              const isAvailable = !selectedColor || availableSizesForColor.includes(size)
              const variantForSize = variants.find(v => v.size === size && v.color === selectedColor)
              
              return (
                <Button
                  key={size}
                  variant={isSelected ? "default" : "outline"}
                  size="sm"
                  className={`${!isAvailable ? 'opacity-50 cursor-not-allowed' : ''}`}
                  onClick={() => isAvailable && handleSizeChange(size)}
                  disabled={!isAvailable}
                >
                  {size}
                  {variantForSize && variantForSize.stock === 0 && (
                    <span className="ml-1 text-xs">(Out of stock)</span>
                  )}
                </Button>
              )
            })}
          </div>
        </div>
      )}

      {/* Stock Status */}
      {selectedVariantData && (
        <div className="flex items-center gap-2">
          <span className="font-medium">Availability:</span>
          {selectedVariantData.stock > 0 ? (
            <Badge variant="default" className="bg-green-100 text-green-800">
              In Stock ({selectedVariantData.stock} available)
            </Badge>
          ) : (
            <Badge variant="destructive">
              Out of Stock
            </Badge>
          )}
        </div>
      )}
    </div>
  )
}
