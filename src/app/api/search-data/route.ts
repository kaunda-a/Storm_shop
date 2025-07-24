import { NextResponse } from 'next/server';
import { db } from '@/lib/prisma';

export async function GET() {
  try {
    // Get popular product names for search suggestions
    const popularProducts = await db.product.findMany({
      where: {
        isActive: true,
        status: 'ACTIVE',
        isFeatured: true, // Use featured products as popular searches
      },
      select: {
        name: true,
        brand: {
          select: {
            name: true
          }
        }
      },
      take: 8,
      orderBy: {
        createdAt: 'desc'
      }
    });

    // Get trending categories (categories with most products)
    const trendingCategories = await db.category.findMany({
      where: {
        isActive: true,
      },
      select: {
        name: true,
        slug: true,
        _count: {
          select: {
            products: {
              where: {
                isActive: true,
                status: 'ACTIVE'
              }
            }
          }
        }
      },
      orderBy: {
        products: {
          _count: 'desc'
        }
      },
      take: 6
    });

    // Create popular searches from product names and brand names
    const popularSearches = [
      ...popularProducts.map((p: any) => p.name),
      ...popularProducts.map((p: any) => p.brand.name),
      // Add some generic popular terms
      'Sneakers',
      'Running Shoes',
      'Formal Shoes',
      'Boots'
    ].filter((value, index, self) => self.indexOf(value) === index) // Remove duplicates
     .slice(0, 8); // Limit to 8 items

    const formattedCategories = trendingCategories
      .filter((cat: any) => cat._count.products > 0)
      .map((cat: any) => ({
        name: cat.name,
        href: `/categories/${cat.slug}`,
        slug: cat.slug
      }));

    const searchData = {
      popularSearches,
      trendingCategories: formattedCategories
    };

    return NextResponse.json(searchData);
  } catch (error) {
    console.error('Error fetching search data:', error);
    return NextResponse.json(
      { error: 'Failed to fetch search data' },
      { status: 500 }
    );
  }
}
