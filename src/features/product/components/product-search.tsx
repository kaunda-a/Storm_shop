'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { IconSearch, IconX, IconClock, IconTrendingUp } from '@tabler/icons-react'
import { useDebounce } from '@/hooks/use-debounce'
import type { ProductSearchProps } from '../types'

interface SearchSuggestion {
  type: 'product' | 'category' | 'brand' | 'recent' | 'trending'
  id: string
  name: string
  category?: string
  brand?: string
}

export function ProductSearch({ 
  placeholder = "Search products...", 
  onSearch,
  initialValue = ""
}: ProductSearchProps) {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [query, setQuery] = useState(initialValue || searchParams.get('search') || '')
  const [isOpen, setIsOpen] = useState(false)
  const [suggestions, setSuggestions] = useState<SearchSuggestion[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [recentSearches, setRecentSearches] = useState<string[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  const debouncedQuery = useDebounce(query, 300)

  // Load recent searches from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('recent-searches')
    if (saved) {
      try {
        setRecentSearches(JSON.parse(saved))
      } catch (error) {
        console.error('Error loading recent searches:', error)
      }
    }
  }, [])

  // Fetch suggestions when query changes
  useEffect(() => {
    if (debouncedQuery.length >= 2) {
      fetchSuggestions(debouncedQuery)
    } else {
      setSuggestions([])
    }
  }, [debouncedQuery])

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const fetchSuggestions = async (searchQuery: string) => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/search-suggestions?q=${encodeURIComponent(searchQuery)}`)
      if (response.ok) {
        const data = await response.json()
        setSuggestions(data.suggestions || [])
      }
    } catch (error) {
      console.error('Error fetching suggestions:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleSearch = (searchQuery: string = query) => {
    if (!searchQuery.trim()) return

    // Save to recent searches
    const newRecentSearches = [
      searchQuery,
      ...recentSearches.filter(s => s !== searchQuery)
    ].slice(0, 5)
    
    setRecentSearches(newRecentSearches)
    localStorage.setItem('recent-searches', JSON.stringify(newRecentSearches))

    // Update URL
    const params = new URLSearchParams(searchParams.toString())
    params.set('search', searchQuery)
    params.delete('page') // Reset to first page
    
    router.push(`/products?${params.toString()}`)
    setIsOpen(false)
    onSearch?.(searchQuery)
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    setQuery(value)
    setIsOpen(value.length > 0)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleSearch()
    } else if (e.key === 'Escape') {
      setIsOpen(false)
      inputRef.current?.blur()
    }
  }

  const handleSuggestionClick = (suggestion: SearchSuggestion) => {
    if (suggestion.type === 'product') {
      router.push(`/products/${suggestion.id}`)
    } else if (suggestion.type === 'category') {
      const params = new URLSearchParams()
      params.set('category', suggestion.id)
      router.push(`/products?${params.toString()}`)
    } else if (suggestion.type === 'brand') {
      const params = new URLSearchParams()
      params.set('brand', suggestion.id)
      router.push(`/products?${params.toString()}`)
    } else {
      handleSearch(suggestion.name)
    }
    setIsOpen(false)
  }

  const clearSearch = () => {
    setQuery('')
    setIsOpen(false)
    const params = new URLSearchParams(searchParams.toString())
    params.delete('search')
    router.push(`/products?${params.toString()}`)
  }

  const clearRecentSearches = () => {
    setRecentSearches([])
    localStorage.removeItem('recent-searches')
  }

  const getSuggestionIcon = (type: string) => {
    switch (type) {
      case 'recent':
        return <IconClock className="h-4 w-4 text-muted-foreground" />
      case 'trending':
        return <IconTrendingUp className="h-4 w-4 text-muted-foreground" />
      default:
        return <IconSearch className="h-4 w-4 text-muted-foreground" />
    }
  }

  return (
    <div ref={containerRef} className="relative w-full max-w-md">
      <div className="relative">
        <IconSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          ref={inputRef}
          type="text"
          placeholder={placeholder}
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          onFocus={() => setIsOpen(query.length > 0 || recentSearches.length > 0)}
          className="pl-10 pr-10"
        />
        {query && (
          <Button
            variant="ghost"
            size="icon"
            className="absolute right-1 top-1/2 transform -translate-y-1/2 h-6 w-6"
            onClick={clearSearch}
          >
            <IconX className="h-4 w-4" />
          </Button>
        )}
      </div>

      {/* Search Suggestions */}
      {isOpen && (
        <Card className="absolute top-full left-0 right-0 mt-1 z-50 max-h-96 overflow-y-auto">
          <CardContent className="p-0">
            {/* Recent Searches */}
            {query.length === 0 && recentSearches.length > 0 && (
              <div className="p-3 border-b">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-muted-foreground">Recent Searches</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearRecentSearches}
                    className="text-xs"
                  >
                    Clear
                  </Button>
                </div>
                <div className="space-y-1">
                  {recentSearches.map((search, index) => (
                    <button
                      key={index}
                      className="flex items-center gap-2 w-full p-2 text-left hover:bg-muted rounded-md transition-colors"
                      onClick={() => handleSearch(search)}
                    >
                      <IconClock className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{search}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Search Suggestions */}
            {query.length >= 2 && (
              <div className="p-3">
                {isLoading ? (
                  <div className="text-center py-4">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary mx-auto"></div>
                  </div>
                ) : suggestions.length > 0 ? (
                  <div className="space-y-1">
                    {suggestions.map((suggestion, index) => (
                      <button
                        key={index}
                        className="flex items-center gap-2 w-full p-2 text-left hover:bg-muted rounded-md transition-colors"
                        onClick={() => handleSuggestionClick(suggestion)}
                      >
                        {getSuggestionIcon(suggestion.type)}
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium truncate">
                            {suggestion.name}
                          </div>
                          {(suggestion.category || suggestion.brand) && (
                            <div className="text-xs text-muted-foreground">
                              {suggestion.category && `in ${suggestion.category}`}
                              {suggestion.brand && ` by ${suggestion.brand}`}
                            </div>
                          )}
                        </div>
                        {suggestion.type !== 'recent' && (
                          <Badge variant="outline" className="text-xs">
                            {suggestion.type}
                          </Badge>
                        )}
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-4 text-sm text-muted-foreground">
                    No suggestions found
                  </div>
                )}
              </div>
            )}

            {/* Search Action */}
            {query.length >= 2 && (
              <div className="p-3 border-t">
                <button
                  className="flex items-center gap-2 w-full p-2 text-left hover:bg-muted rounded-md transition-colors"
                  onClick={() => handleSearch()}
                >
                  <IconSearch className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">Search for "{query}"</span>
                </button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
