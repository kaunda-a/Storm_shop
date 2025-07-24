'use client'

import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { Progress } from '@/components/ui/progress'
import { IconStar, IconThumbUp, IconThumbDown } from '@tabler/icons-react'
import { formatDistanceToNow } from 'date-fns'
import type { ProductReviewsProps } from '../types'

interface Review {
  id: string
  rating: number
  title: string
  content: string
  customerName: string
  customerAvatar?: string
  createdAt: string
  verified: boolean
  helpful: number
  notHelpful: number
}

interface ReviewStats {
  averageRating: number
  totalReviews: number
  ratingDistribution: { [key: number]: number }
}

export function ProductReviews({ 
  productId, 
  averageRating = 0, 
  totalReviews = 0 
}: ProductReviewsProps) {
  const [reviews, setReviews] = useState<Review[]>([])
  const [stats, setStats] = useState<ReviewStats>({
    averageRating,
    totalReviews,
    ratingDistribution: {}
  })
  const [isLoading, setIsLoading] = useState(true)
  const [currentPage, setCurrentPage] = useState(1)
  const [sortBy, setSortBy] = useState('newest')

  useEffect(() => {
    fetchReviews()
  }, [productId, currentPage, sortBy])

  const fetchReviews = async () => {
    setIsLoading(true)
    try {
      const response = await fetch(
        `/api/products/${productId}/reviews?page=${currentPage}&sort=${sortBy}`
      )
      if (response.ok) {
        const data = await response.json()
        setReviews(data.reviews || [])
        setStats(data.stats || stats)
      }
    } catch (error) {
      console.error('Error fetching reviews:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleHelpful = async (reviewId: string, helpful: boolean) => {
    try {
      await fetch(`/api/reviews/${reviewId}/helpful`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ helpful })
      })
      // Refresh reviews to get updated counts
      fetchReviews()
    } catch (error) {
      console.error('Error marking review as helpful:', error)
    }
  }

  const renderStars = (rating: number, size: 'sm' | 'md' | 'lg' = 'sm') => {
    const sizeClass = {
      sm: 'h-3 w-3',
      md: 'h-4 w-4',
      lg: 'h-5 w-5'
    }[size]

    return (
      <div className="flex items-center">
        {[...Array(5)].map((_, i) => (
          <IconStar
            key={i}
            className={`${sizeClass} ${
              i < rating ? 'fill-yellow-400 text-yellow-400' : 'text-gray-300'
            }`}
          />
        ))}
      </div>
    )
  }

  const getRatingPercentage = (rating: number) => {
    if (stats.totalReviews === 0) return 0
    return ((stats.ratingDistribution[rating] || 0) / stats.totalReviews) * 100
  }

  if (isLoading && reviews.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Customer Reviews</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="flex items-center gap-4 mb-2">
                  <div className="w-10 h-10 bg-gray-200 rounded-full"></div>
                  <div className="flex-1">
                    <div className="h-4 bg-gray-200 rounded w-1/4 mb-1"></div>
                    <div className="h-3 bg-gray-200 rounded w-1/6"></div>
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                  <div className="h-4 bg-gray-200 rounded w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Customer Reviews</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Review Summary */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Overall Rating */}
          <div className="text-center space-y-2">
            <div className="text-4xl font-bold">{stats.averageRating.toFixed(1)}</div>
            {renderStars(Math.round(stats.averageRating), 'lg')}
            <p className="text-sm text-muted-foreground">
              Based on {stats.totalReviews} reviews
            </p>
          </div>

          {/* Rating Distribution */}
          <div className="space-y-2">
            {[5, 4, 3, 2, 1].map((rating) => (
              <div key={rating} className="flex items-center gap-2">
                <span className="text-sm w-8">{rating}</span>
                <IconStar className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                <Progress 
                  value={getRatingPercentage(rating)} 
                  className="flex-1 h-2" 
                />
                <span className="text-sm text-muted-foreground w-12">
                  {stats.ratingDistribution[rating] || 0}
                </span>
              </div>
            ))}
          </div>
        </div>

        {stats.totalReviews > 0 && (
          <>
            <Separator />

            {/* Sort Options */}
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Sort by:</span>
              <div className="flex gap-2">
                {[
                  { value: 'newest', label: 'Newest' },
                  { value: 'oldest', label: 'Oldest' },
                  { value: 'highest', label: 'Highest Rated' },
                  { value: 'lowest', label: 'Lowest Rated' },
                  { value: 'helpful', label: 'Most Helpful' }
                ].map((option) => (
                  <Button
                    key={option.value}
                    variant={sortBy === option.value ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setSortBy(option.value)}
                  >
                    {option.label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Reviews List */}
            <div className="space-y-6">
              {reviews.map((review) => (
                <div key={review.id} className="space-y-3">
                  <div className="flex items-start gap-4">
                    <Avatar>
                      <AvatarImage src={review.customerAvatar} />
                      <AvatarFallback>
                        {review.customerName.slice(0, 2).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{review.customerName}</span>
                        {review.verified && (
                          <Badge variant="secondary" className="text-xs">
                            Verified Purchase
                          </Badge>
                        )}
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {renderStars(review.rating)}
                        <span className="text-sm text-muted-foreground">
                          {formatDistanceToNow(new Date(review.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      
                      {review.title && (
                        <h4 className="font-medium">{review.title}</h4>
                      )}
                      
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        {review.content}
                      </p>
                      
                      <div className="flex items-center gap-4">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleHelpful(review.id, true)}
                          className="text-xs"
                        >
                          <IconThumbUp className="h-3 w-3 mr-1" />
                          Helpful ({review.helpful})
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleHelpful(review.id, false)}
                          className="text-xs"
                        >
                          <IconThumbDown className="h-3 w-3 mr-1" />
                          Not Helpful ({review.notHelpful})
                        </Button>
                      </div>
                    </div>
                  </div>
                  
                  {review !== reviews[reviews.length - 1] && <Separator />}
                </div>
              ))}
            </div>

            {/* Load More */}
            {reviews.length > 0 && reviews.length < stats.totalReviews && (
              <div className="text-center">
                <Button
                  variant="outline"
                  onClick={() => setCurrentPage(prev => prev + 1)}
                  disabled={isLoading}
                >
                  {isLoading ? 'Loading...' : 'Load More Reviews'}
                </Button>
              </div>
            )}
          </>
        )}

        {stats.totalReviews === 0 && (
          <div className="text-center py-8">
            <p className="text-muted-foreground">No reviews yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Be the first to review this product
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
