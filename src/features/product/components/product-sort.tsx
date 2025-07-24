'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ProductSortProps } from '../types'

const sortOptions = [
  { value: 'newest', label: 'Newest First' },
  { value: 'oldest', label: 'Oldest First' },
  { value: 'price-low-high', label: 'Price: Low to High' },
  { value: 'price-high-low', label: 'Price: High to Low' },
  { value: 'name-a-z', label: 'Name: A to Z' },
  { value: 'name-z-a', label: 'Name: Z to A' },
  { value: 'featured', label: 'Featured' },
  { value: 'rating', label: 'Highest Rated' },
]

export function ProductSort({ currentSort, onSortChange }: ProductSortProps) {
  const router = useRouter()
  const searchParams = useSearchParams()

  const handleSortChange = (value: string) => {
    const params = new URLSearchParams(searchParams.toString())
    
    if (value === 'newest') {
      params.delete('sort')
    } else {
      params.set('sort', value)
    }
    
    // Reset to first page when sort changes
    params.delete('page')
    
    router.push(`?${params.toString()}`)
    onSortChange?.(value)
  }

  const selectedSort = currentSort || searchParams.get('sort') || 'newest'

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm font-medium whitespace-nowrap">Sort by:</span>
      <Select value={selectedSort} onValueChange={handleSortChange}>
        <SelectTrigger className="w-[180px]">
          <SelectValue placeholder="Select sort option" />
        </SelectTrigger>
        <SelectContent>
          {sortOptions.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}
