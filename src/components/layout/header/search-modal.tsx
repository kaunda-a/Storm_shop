'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Dialog,
  DialogContent,
  DialogHeader,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import {
  IconSearch,
  IconClock,
  IconTrendingUp,
  IconX
} from '@tabler/icons-react';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface SearchData {
  popularSearches: string[];
  trendingCategories: Array<{ name: string; href: string; slug: string }>;
}

export function SearchModal({ isOpen, onClose }: SearchModalProps) {
  const [query, setQuery] = useState('');
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [searchData, setSearchData] = useState<SearchData | null>(null);
  const [loading, setLoading] = useState(true);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    // Load recent searches from localStorage
    const saved = localStorage.getItem('recentSearches');
    if (saved) {
      setRecentSearches(JSON.parse(saved));
    }

    // Fetch search data
    async function fetchSearchData() {
      try {
        setLoading(true);
        const response = await fetch('/api/search-data');
        if (response.ok) {
          const data = await response.json();
          setSearchData(data);
        }
      } catch (error) {
        console.error('Error fetching search data:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchSearchData();
  }, []);

  const handleSearch = (searchQuery: string) => {
    if (!searchQuery.trim()) return;

    // Add to recent searches
    const updated = [searchQuery, ...recentSearches.filter(s => s !== searchQuery)].slice(0, 5);
    setRecentSearches(updated);
    localStorage.setItem('recentSearches', JSON.stringify(updated));

    // Navigate to search results
    router.push(`/search?q=${encodeURIComponent(searchQuery)}`);
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch(query);
    }
  };

  const clearRecentSearches = () => {
    setRecentSearches([]);
    localStorage.removeItem('recentSearches');
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl p-0">
        <DialogHeader className="p-6 pb-0">
          <div className="relative">
            <Input
              ref={inputRef}
              type="text"
              placeholder="Search for shoes, brands, styles..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              className="pl-10 pr-4 py-3 text-lg"
            />
            <IconSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            {query && (
              <Button
                variant="ghost"
                size="sm"
                className="absolute right-2 top-1/2 transform -translate-y-1/2"
                onClick={() => setQuery('')}
              >
                <IconX className="h-4 w-4" />
              </Button>
            )}
          </div>
        </DialogHeader>

        <div className="max-h-96 overflow-y-auto">
          {query ? (
            // Search suggestions (you can implement actual search API here)
            <div className="p-6 pt-0">
              <Button
                variant="ghost"
                className="w-full justify-start text-left"
                onClick={() => handleSearch(query)}
              >
                <IconSearch className="mr-3 h-4 w-4" />
                Search for "{query}"
              </Button>
            </div>
          ) : (
            <div className="p-6 pt-0 space-y-6">
              {/* Recent Searches */}
              {recentSearches.length > 0 && (
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-medium text-sm text-gray-900 flex items-center">
                      <IconClock className="mr-2 h-4 w-4" />
                      Recent Searches
                    </h3>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={clearRecentSearches}
                      className="text-xs text-gray-500"
                    >
                      Clear
                    </Button>
                  </div>
                  <div className="space-y-1">
                    {recentSearches.map((search, index) => (
                      <Button
                        key={index}
                        variant="ghost"
                        className="w-full justify-start text-left"
                        onClick={() => handleSearch(search)}
                      >
                        <IconClock className="mr-3 h-4 w-4 text-gray-400" />
                        {search}
                      </Button>
                    ))}
                  </div>
                </div>
              )}

              {/* Popular Searches */}
              {searchData && searchData.popularSearches.length > 0 && (
                <div>
                  <h3 className="font-medium text-sm text-gray-900 mb-3 flex items-center">
                    <IconTrendingUp className="mr-2 h-4 w-4" />
                    Popular Searches
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {searchData.popularSearches.map((search) => (
                      <Badge
                        key={search}
                        variant="secondary"
                        className="cursor-pointer hover:bg-gray-200"
                        onClick={() => handleSearch(search)}
                      >
                        {search}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {searchData && searchData.popularSearches.length > 0 && <Separator />}

              {/* Trending Categories */}
              {searchData && searchData.trendingCategories.length > 0 && (
                <div>
                  <h3 className="font-medium text-sm text-gray-900 mb-3">
                    Browse Categories
                  </h3>
                  <div className="grid grid-cols-2 gap-2">
                    {searchData.trendingCategories.map((category) => (
                      <Button
                        key={category.name}
                        variant="outline"
                        className="justify-start"
                        asChild
                        onClick={onClose}
                      >
                        <Link href={`/categories/${category.slug}`}>
                          {category.name}
                        </Link>
                      </Button>
                    ))}
                  </div>
                </div>
              )}

              {loading && (
                <div className="space-y-4">
                  <div className="h-4 bg-gray-200 rounded animate-pulse" />
                  <div className="h-16 bg-gray-200 rounded animate-pulse" />
                </div>
              )}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
