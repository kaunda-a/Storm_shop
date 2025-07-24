'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useSession, signOut } from 'next-auth/react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Sheet,
  SheetContent,
  SheetTrigger,
} from '@/components/ui/sheet';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  IconMenu2,
  IconSearch,
  IconShoppingCart,
  IconUser,
  IconHeart,
  IconLogout,
  IconPackage,
  IconMapPin,
  IconPhone
} from '@tabler/icons-react';
import { useCartStore } from '@/lib/cart-store';
import { CartDrawer } from '../cart/cart-drawer';
import { SearchModal } from './search-modal';
import { MegaMenu } from './mega-menu';
import { MobileMenu } from './mobile-menu';

interface NavigationItem {
  name: string;
  href: string;
  featured?: Array<{
    name: string;
    href: string;
    slug: string;
  }>;
}

interface NavigationData {
  categories: Array<{
    id: string;
    name: string;
    slug: string;
    subcategories?: Array<{
      name: string;
      slug: string;
    }>;
  }>;
  brands: Array<{
    id: string;
    name: string;
    slug: string;
  }>;
}

export function Header() {
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [navigation, setNavigation] = useState<NavigationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const { data: session } = useSession();
  const { totalItems, openCart } = useCartStore();

  useEffect(() => {
    async function fetchNavigation() {
      try {
        setLoading(true);
        const response = await fetch('/api/navigation');
        if (response.ok) {
          const data: NavigationData = await response.json();

          // Build navigation items from API data
          const navItems: NavigationItem[] = [
            { name: 'Products', href: '/products' },
            {
              name: 'Categories',
              href: '/categories',
              featured: data.categories.slice(0, 6).map(cat => ({
                name: cat.name,
                href: `/categories/${cat.slug}`,
                slug: cat.slug
              }))
            },
            {
              name: 'Brands',
              href: '/brands',
              featured: data.brands.slice(0, 6).map(brand => ({
                name: brand.name,
                href: `/brands/${brand.slug}`,
                slug: brand.slug
              }))
            },
            { name: 'Promotions', href: '/billboards' },
            { name: 'Messages', href: '/marquee' },
            { name: 'Sale', href: '/sale' },
          ];

          setNavigation(navItems);
        }
      } catch (error) {
        console.error('Error fetching navigation:', error);
        // Fallback to static navigation
        setNavigation([
          { name: 'Products', href: '/products' },
          { name: 'Categories', href: '/categories' },
          { name: 'Brands', href: '/brands' },
          { name: 'Promotions', href: '/billboards' },
          { name: 'Messages', href: '/marquee' },
          { name: 'Sale', href: '/sale' },
        ]);
      } finally {
        setLoading(false);
      }
    }

    fetchNavigation();
  }, []);

  return (
    <>
      {/* Top Bar */}
      <div className="bg-slate-900 text-white text-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-10">
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <IconPhone className="h-4 w-4" />
                <span>+27 11 123 4567</span>
              </div>
              <div className="hidden md:flex items-center space-x-2">
                <IconMapPin className="h-4 w-4" />
                <span>Free delivery in Johannesburg</span>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/track-order" className="hover:text-gray-300">
                Track Order
              </Link>
              <Link href="/help" className="hover:text-gray-300">
                Help
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Main Header */}
      <header className="bg-white shadow-sm border-b sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Mobile menu button */}
            <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="sm" className="md:hidden">
                  <IconMenu2 className="h-6 w-6" />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-80">
                <MobileMenu navigation={navigation} onClose={() => setIsMobileMenuOpen(false)} />
              </SheetContent>
            </Sheet>

            {/* Logo */}
            <Link href="/" className="flex items-center space-x-2">
              <div className="bg-slate-900 text-white p-2 rounded-lg">
                <span className="font-bold text-lg">MF</span>
              </div>
              <div className="hidden sm:block">
                <span className="font-bold text-xl text-slate-900">Mzansi</span>
                <span className="font-light text-xl text-slate-600">Footwear</span>
              </div>
            </Link>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex space-x-8">
              {loading ? (
                // Loading skeleton
                [...Array(4)].map((_, i) => (
                  <div key={i} className="h-6 w-16 bg-gray-200 rounded animate-pulse" />
                ))
              ) : (
                navigation.map((item) => (
                  item.featured ? (
                    <MegaMenu key={item.name} item={item} />
                  ) : (
                    <Button key={item.name} variant="ghost" asChild>
                      <Link href={item.href} className="font-medium">
                        {item.name}
                      </Link>
                    </Button>
                  )
                ))
              )}
            </nav>

            {/* Search Bar - Desktop */}
            <div className="hidden lg:flex flex-1 max-w-lg mx-8">
              <div className="relative w-full">
                <Input
                  type="text"
                  placeholder="Search for shoes, brands..."
                  className="pl-10 pr-4 py-2 w-full"
                  onClick={() => setIsSearchOpen(true)}
                />
                <IconSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              </div>
            </div>

            {/* Right side actions */}
            <div className="flex items-center space-x-4">
              {/* Search - Mobile */}
              <Button
                variant="ghost"
                size="sm"
                className="lg:hidden"
                onClick={() => setIsSearchOpen(true)}
              >
                <IconSearch className="h-5 w-5" />
              </Button>

              {/* Wishlist */}
              <Button variant="ghost" size="sm" asChild>
                <Link href="/wishlist">
                  <IconHeart className="h-5 w-5" />
                </Link>
              </Button>

              {/* Cart */}
              <Button
                variant="ghost"
                size="sm"
                className="relative"
                onClick={openCart}
              >
                <IconShoppingCart className="h-5 w-5" />
                {totalItems > 0 && (
                  <Badge 
                    variant="destructive" 
                    className="absolute -top-2 -right-2 h-5 w-5 flex items-center justify-center text-xs"
                  >
                    {totalItems}
                  </Badge>
                )}
              </Button>

              {/* User Account */}
              {session ? (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm">
                      <Avatar className="h-8 w-8">
                        <AvatarImage src={session.user?.image || ''} />
                        <AvatarFallback>
                          {session.user?.name?.charAt(0) || 'U'}
                        </AvatarFallback>
                      </Avatar>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-56">
                    <DropdownMenuLabel>
                      {session.user?.name || 'My Account'}
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem asChild>
                      <Link href="/account">
                        <IconUser className="mr-2 h-4 w-4" />
                        Profile
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link href="/orders">
                        <IconPackage className="mr-2 h-4 w-4" />
                        Orders
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link href="/wishlist">
                        <IconHeart className="mr-2 h-4 w-4" />
                        Wishlist
                      </Link>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => signOut({ callbackUrl: '/' })}>
                      <IconLogout className="mr-2 h-4 w-4" />
                      Sign out
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              ) : (
                <div className="flex items-center space-x-2">
                  <Button variant="ghost" size="sm" asChild>
                    <Link href="/auth/customer-sign-in">Sign In</Link>
                  </Button>
                  <Button size="sm" asChild>
                    <Link href="/auth/customer-sign-in">Sign Up</Link>
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Search Modal */}
      <SearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
      
      {/* Cart Drawer */}
      <CartDrawer />
    </>
  );
}
