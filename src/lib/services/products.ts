import { db } from '@/lib/prisma'
import type { Product, Category, Brand, ProductVariant, ProductImage, Prisma, ProductStatus } from '@prisma/client'
import { Decimal } from '@prisma/client/runtime/library'

export type ProductWithDetails = Product & {
  category: Category
  brand: Brand
  variants: Array<Omit<ProductVariant, 'price' | 'comparePrice' | 'costPrice' | 'weight'> & {
    price: Decimal;
    comparePrice: Decimal | null;
    costPrice: Decimal | null;
    weight: Decimal | null;
  }>
  images: { id: string; url: string; altText: string | null; isPrimary: boolean }[]
  _count: {
    reviews: number
  }
}

export type ProductFilters = {
  search?: string
  categoryId?: string
  brandId?: string
  status?: ProductStatus
  isActive?: boolean
  isFeatured?: boolean
  minPrice?: number
  maxPrice?: number
}

export type ProductSort = {
  field: 'name' | 'createdAt' | 'updatedAt' | 'price'
  direction: 'asc' | 'desc'
}

export class ProductService {
  static async getProducts({
    filters = {},
    sort = { field: 'createdAt', direction: 'desc' },
    page = 1,
    limit = 10
  }: {
    filters?: ProductFilters
    sort?: ProductSort
    page?: number
    limit?: number
  } = {}) {
    const skip = (page - 1) * limit

    const where: any = {}

    // Apply filters
    if (filters.search) {
      where.OR = [
        { name: { contains: filters.search, mode: 'insensitive' } },
        { description: { contains: filters.search, mode: 'insensitive' } },
        { sku: { contains: filters.search, mode: 'insensitive' } }
      ]
    }

    if (filters.categoryId) where.categoryId = filters.categoryId
    if (filters.brandId) where.brandId = filters.brandId
    if (filters.status) where.status = filters.status
    if (filters.isActive !== undefined) where.isActive = filters.isActive
    if (filters.isFeatured !== undefined) where.isFeatured = filters.isFeatured

    // Price filtering (based on variants)
    if (filters.minPrice || filters.maxPrice) {
      where.variants = {
        some: {
          price: {
            ...(filters.minPrice && { gte: filters.minPrice }),
            ...(filters.maxPrice && { lte: filters.maxPrice })
          }
        }
      }
    }

    const orderBy: any = {}
    if (sort.field === 'price') {
      // Sort by minimum variant price
      orderBy.variants = {
        _min: {
          price: sort.direction
        }
      }
    } else {
      orderBy[sort.field] = sort.direction
    }

    const [products, total] = await Promise.all([
      db.product.findMany({
        where,
        include: {
          category: true,
          brand: true,
          variants: {
            orderBy: { price: 'asc' },
            take: 1 // Get cheapest variant for display
          },
          images: {
            orderBy: { sortOrder: 'asc' }
          },
          _count: {
            select: { reviews: true }
          }
        },
        orderBy,
        skip,
        take: limit
      }),
      db.product.count({ where })
    ])

    return {
      products: products.map(product => ({
        ...product,
        variants: product.variants.map(variant => ({
          ...variant,
          price: variant.price,
          comparePrice: variant.comparePrice,
          costPrice: variant.costPrice,
          weight: variant.weight
        }))
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  }

  static async getProductBySlug(slug: string): Promise<ProductWithDetails | null> {
    return db.product.findUnique({
      where: { slug },
      include: {
        category: true,
        brand: true,
        variants: {
          where: { isActive: true },
          orderBy: { price: 'asc' }
        },
        images: {
          orderBy: { sortOrder: 'asc' }
        },
        _count: {
          select: { reviews: true }
        }
      }
    }) as Promise<ProductWithDetails | null>
  }

  static async getProductById(id: string): Promise<ProductWithDetails | null> {
    const product = await db.product.findUnique({
      where: { id },
      include: {
        category: true,
        brand: true,
        variants: {
          orderBy: { price: 'asc' }
        },
        images: {
          orderBy: { sortOrder: 'asc' }
        },
        _count: {
          select: { reviews: true }
        }
      }
    })

    if (!product) return null

    return {
      ...product,
      variants: product.variants.map(variant => ({
        ...variant,
        price: variant.price,
        comparePrice: variant.comparePrice,
        costPrice: variant.costPrice,
        weight: variant.weight
      }))
    }
  }

  static async getFeaturedProducts(limit = 8): Promise<ProductWithDetails[]> {
    return db.product.findMany({
      where: {
        isFeatured: true,
        isActive: true,
        status: 'ACTIVE'
      },
      include: {
        category: true,
        brand: true,
        variants: {
          where: { isActive: true },
          orderBy: { price: 'asc' },
          take: 1
        },
        images: {
          where: { isPrimary: true },
          take: 1
        },
        _count: {
          select: { reviews: true }
        }
      },
      take: limit,
      orderBy: { createdAt: 'desc' }
    })
  }

  static async getCategories() {
    return db.category.findMany({
      where: { isActive: true },
      include: {
        _count: {
          select: { products: true }
        }
      },
      orderBy: { sortOrder: 'asc' }
    })
  }

  static async getCategoryById(id: string) {
    return db.category.findUnique({
      where: { id },
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async createCategory(data: {
    name: string
    description?: string
    imageUrl?: string
    isActive: boolean
  }) {
    // Generate slug from name
    const slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')

    return db.category.create({
      data: {
        name: data.name,
        slug,
        description: data.description,
        imageUrl: data.imageUrl,
        isActive: data.isActive
      },
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async updateCategory(id: string, data: {
    name?: string
    description?: string
    imageUrl?: string
    isActive?: boolean
  }) {
    return db.category.update({
      where: { id },
      data,
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async deleteCategory(id: string) {
    return db.category.delete({
      where: { id }
    })
  }

  static async getProductsCountByCategory(categoryId: string) {
    return db.product.count({
      where: { categoryId }
    })
  }

  static async getBrands() {
    return db.brand.findMany({
      where: { isActive: true },
      include: {
        _count: {
          select: { products: true }
        }
      },
      orderBy: { name: 'asc' }
    })
  }

  static async getBrandById(id: string) {
    return db.brand.findUnique({
      where: { id },
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async createBrand(data: {
    name: string
    description?: string
    logoUrl?: string
    websiteUrl?: string
    isActive: boolean
  }) {
    // Generate slug from name
    const slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')

    return db.brand.create({
      data: {
        name: data.name,
        slug,
        description: data.description,
        logoUrl: data.logoUrl,
        website: data.websiteUrl,
        isActive: data.isActive
      },
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async updateBrand(id: string, data: {
    name?: string
    description?: string
    logoUrl?: string
    websiteUrl?: string
    isActive?: boolean
  }) {
    return db.brand.update({
      where: { id },
      data,
      include: {
        _count: {
          select: { products: true }
        }
      }
    })
  }

  static async deleteBrand(id: string) {
    return db.brand.delete({
      where: { id }
    })
  }

  static async getProductsCountByBrand(brandId: string) {
    return db.product.count({
      where: { brandId }
    })
  }

  static async getProductVariants(productId: string) {
    const variants = await db.productVariant.findMany({
      where: {
        productId,
        isActive: true
      },
      orderBy: { price: 'asc' }
    })

    return variants.map(variant => ({
      ...variant,
      price: Number(variant.price),
      comparePrice: variant.comparePrice ? Number(variant.comparePrice) : null,
      costPrice: variant.costPrice ? Number(variant.costPrice) : null,
      weight: variant.weight ? Number(variant.weight) : null
    }))
  }

  static async updateStock(variantId: string, quantity: number) {
    return db.productVariant.update({
      where: { id: variantId },
      data: {
        stock: {
          decrement: quantity
        }
      }
    })
  }

  static async createProduct(data: {
    name: string
    description: string
    sku: string
    price: number
    compareAtPrice?: number
    costPrice?: number
    trackQuantity: boolean
    quantity: number
    lowStockThreshold?: number
    weight?: number
    categoryId: string
    brandId: string
    tags?: string[]
    isActive: boolean
    isFeatured: boolean
    images?: string[]
    createdBy: string
  }) {
    // Generate slug from name
    const slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')

    return db.product.create({
      data: {
        name: data.name,
        slug,
        description: data.description,
        sku: data.sku,
        categoryId: data.categoryId,
        brandId: data.brandId,
        status: data.isActive ? 'ACTIVE' : 'DRAFT',
        isActive: data.isActive,
        isFeatured: data.isFeatured,
        tags: data.tags || [],
        // Create default variant with pricing info
        variants: {
          create: {
            size: 'Default',
            color: 'Default',
            sku: data.sku,
            price: data.price,
            comparePrice: data.compareAtPrice,
            costPrice: data.costPrice,
            stock: data.quantity,
            lowStockThreshold: data.lowStockThreshold || 5,
            weight: data.weight,
            isActive: true
          }
        },
        // Create images if provided
        ...(data.images && data.images.length > 0 && {
          images: {
            create: data.images.map((url, index) => ({
              url,
              altText: data.name,
              isPrimary: index === 0,
              sortOrder: index
            }))
          }
        })
      },
      include: {
        category: true,
        brand: true,
        variants: true,
        images: true,
        _count: {
          select: { reviews: true }
        }
      }
    })
  }

  static async updateProduct(id: string, data: {
    name?: string
    description?: string
    sku?: string
    price?: number
    compareAtPrice?: number
    costPrice?: number
    trackQuantity?: boolean
    quantity?: number
    lowStockThreshold?: number
    weight?: number
    categoryId?: string
    brandId?: string
    tags?: string[]
    isActive?: boolean
    isFeatured?: boolean
    images?: string[]
  }) {
    const updateData: any = {}

    // Update product fields
    if (data.name) {
      updateData.name = data.name
      updateData.slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
    }
    if (data.description !== undefined) updateData.description = data.description
    if (data.sku) updateData.sku = data.sku
    if (data.categoryId) updateData.categoryId = data.categoryId
    if (data.brandId) updateData.brandId = data.brandId
    if (data.tags !== undefined) updateData.tags = data.tags
    if (data.isActive !== undefined) {
      updateData.isActive = data.isActive
      updateData.status = data.isActive ? 'ACTIVE' : 'DRAFT'
    }
    if (data.isFeatured !== undefined) updateData.isFeatured = data.isFeatured

    // Update default variant if pricing/inventory data provided
    const variantUpdate: any = {}
    if (data.price !== undefined) variantUpdate.price = data.price
    if (data.compareAtPrice !== undefined) variantUpdate.comparePrice = data.compareAtPrice
    if (data.costPrice !== undefined) variantUpdate.costPrice = data.costPrice
    if (data.quantity !== undefined) variantUpdate.stock = data.quantity
    if (data.lowStockThreshold !== undefined) variantUpdate.lowStockThreshold = data.lowStockThreshold
    if (data.weight !== undefined) variantUpdate.weight = data.weight

    return db.product.update({
      where: { id },
      data: {
        ...updateData,
        // Update default variant if we have variant data
        ...(Object.keys(variantUpdate).length > 0 && {
          variants: {
            updateMany: {
              where: { isDefault: true },
              data: variantUpdate
            }
          }
        }),
        // Handle images update if provided
        ...(data.images && {
          images: {
            deleteMany: {},
            create: data.images.map((url, index) => ({
              url,
              altText: data.name || 'Product image',
              isPrimary: index === 0,
              sortOrder: index
            }))
          }
        })
      },
      include: {
        category: true,
        brand: true,
        variants: true,
        images: true,
        _count: {
          select: { reviews: true }
        }
      }
    })
  }

  static async deleteProduct(id: string) {
    // Delete in correct order due to foreign key constraints
    await db.productImage.deleteMany({ where: { productId: id } })
    await db.productVariant.deleteMany({ where: { productId: id } })
    return db.product.delete({ where: { id } })
  }

  static async getProductStats() {
    const [totalProducts, activeProducts, lowStockVariants, categories] = await Promise.all([
      db.product.count(),
      db.product.count({ where: { isActive: true, status: 'ACTIVE' } }),
      db.productVariant.count({
        where: {
          stock: {
            lte: db.productVariant.fields.lowStockThreshold
          }
        }
      }),
      db.category.count({ where: { isActive: true } })
    ])

    return {
      totalProducts,
      activeProducts,
      lowStockVariants,
      categories
    }
  }
}
