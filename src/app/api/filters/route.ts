import { NextResponse } from 'next/server';
import { db } from '@/lib/prisma';

export async function GET() {
  try {
    // Get categories with product counts
    const categories = await db.category.findMany({
      where: {
        isActive: true,
      },
      select: {
        id: true,
        name: true,
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
        name: 'asc'
      }
    });

    // Get brands with product counts
    const brands = await db.brand.findMany({
      where: {
        isActive: true,
      },
      select: {
        id: true,
        name: true,
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
        name: 'asc'
      }
    });

    // Get unique sizes from variants
    const sizeData = await db.productVariant.groupBy({
      by: ['size'],
      where: {
        isActive: true,
        product: {
          isActive: true,
          status: 'ACTIVE'
        }
      },
      _count: {
        size: true
      },
      orderBy: {
        size: 'asc'
      }
    });

    // Get unique colors from variants
    const colorData = await db.productVariant.groupBy({
      by: ['color'],
      where: {
        isActive: true,
        product: {
          isActive: true,
          status: 'ACTIVE'
        }
      },
      _count: {
        color: true
      },
      orderBy: {
        color: 'asc'
      }
    });

    // Format the data
    const formattedCategories = categories.map((cat: any) => ({
      id: cat.id,
      name: cat.name,
      count: cat._count.products
    }));

    const formattedBrands = brands.map((brand: any) => ({
      id: brand.id,
      name: brand.name,
      count: brand._count.products
    }));

    const formattedSizes = sizeData.map((size: any) => ({
      value: size.size,
      label: size.size,
      count: size._count.size
    }));

    // Create a color mapping for hex values
    const colorHexMap: Record<string, string> = {
      'black': '#000000',
      'white': '#FFFFFF',
      'brown': '#8B4513',
      'blue': '#0000FF',
      'red': '#FF0000',
      'gray': '#808080',
      'grey': '#808080',
      'green': '#008000',
      'yellow': '#FFFF00',
      'orange': '#FFA500',
      'purple': '#800080',
      'pink': '#FFC0CB',
      'navy': '#000080',
      'beige': '#F5F5DC',
      'tan': '#D2B48C',
      'silver': '#C0C0C0',
      'gold': '#FFD700',
    };

    const formattedColors = colorData.map((color: any) => ({
      value: color.color.toLowerCase(),
      label: color.color,
      hex: colorHexMap[color.color.toLowerCase()] || '#808080',
      count: color._count.color
    }));

    const filterData = {
      categories: formattedCategories,
      brands: formattedBrands,
      sizes: formattedSizes,
      colors: formattedColors
    };

    return NextResponse.json(filterData);
  } catch (error) {
    console.error('Error fetching filter data:', error);
    return NextResponse.json(
      { error: 'Failed to fetch filter data' },
      { status: 500 }
    );
  }
}
