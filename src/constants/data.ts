import { NavItem } from '@/types';

// Utility function for delays (used in parallel routes)
export const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

//Info: The following data is used for shop navigation and search.
export const shopNavItems = [
  {
    title: 'Home',
    url: '/',
    shortcut: ['h', 'h']
  },
  {
    title: 'Products',
    url: '/products',
    shortcut: ['p', 'p']
  },
  {
    title: 'Categories',
    url: '/categories',
    shortcut: ['c', 'c']
  },
  {
    title: 'Brands',
    url: '/brands',
    shortcut: ['b', 'b']
  },
  {
    title: 'Sale',
    url: '/sale',
    shortcut: ['s', 's']
  },
  {
    title: 'Account',
    url: '/account',
    shortcut: ['a', 'a']
  },
  {
    title: 'Orders',
    url: '/orders',
    shortcut: ['o', 'o']
  },
  {
    title: 'Wishlist',
    url: '/wishlist',
    shortcut: ['w', 'w']
  },
  {
    title: 'Cart',
    url: '/cart',
    shortcut: ['c', 'a']
  }
];

// Legacy admin nav items (kept for compatibility)
export const navItems: NavItem[] = [
  {
    title: 'Kanban',
    url: '/dashboard/kanban',
    icon: 'kanban',
    shortcut: ['k', 'k'],
    isActive: false,
    items: [] // No child items
  }
];




