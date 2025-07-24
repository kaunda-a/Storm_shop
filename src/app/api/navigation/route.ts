import { NextResponse } from 'next/server';
import { db } from '@/lib/prisma';

export async function GET() {
  try {
    // Get active categories for navigation
    const categories = await db.category.findMany({
      where: {
        isActive: true,
      },
      select: {
        id: true,
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
      orderBy: [
        { 
          products: {
            _count: 'desc' // Order by product count (most popular first)
          }
        },
        { name: 'asc' }
      ],
      take: 10 // Limit to top 10 categories
    });

    // Get active brands for navigation
    const brands = await db.brand.findMany({
      where: {
        isActive: true,
      },
      select: {
        id: true,
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
      orderBy: [
        { 
          products: {
            _count: 'desc' // Order by product count (most popular first)
          }
        },
        { name: 'asc' }
      ],
      take: 10 // Limit to top 10 brands
    });

    // Filter out categories and brands with no products
    const filteredCategories = categories.filter((cat: any) => cat._count.products > 0);
    const filteredBrands = brands.filter((brand: any) => brand._count.products > 0);

    const navigationData = {
      categories: filteredCategories.map((cat: any) => ({
        id: cat.id,
        name: cat.name,
        slug: cat.slug,
        productCount: cat._count.products
      })),
      brands: filteredBrands.map((brand: any) => ({
        id: brand.id,
        name: brand.name,
        slug: brand.slug,
        productCount: brand._count.products
      }))
    };

    return NextResponse.json(navigationData);
  } catch (error) {
    console.error('Error fetching navigation data:', error);
    return NextResponse.json(
      { error: 'Failed to fetch navigation data' },
      { status: 500 }
    );
  }
}
