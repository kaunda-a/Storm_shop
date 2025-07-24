import { db } from '@/lib/prisma'
import type { AnalyticsEventType } from '@prisma/client'

export type DashboardStats = {
  totalRevenue: number
  totalOrders: number
  totalCustomers: number
  totalProducts: number
  revenueGrowth: number
  ordersGrowth: number
  customersGrowth: number
  productsGrowth: number
}

export type SalesData = {
  date: string
  revenue: number
  orders: number
}

export type TopProduct = {
  id: string
  name: string
  slug: string
  totalSold: number
  revenue: number
  image?: string
}

export type CategoryPerformance = {
  id: string
  name: string
  totalSold: number
  revenue: number
  percentage: number
}

export class AnalyticsService {
  static async getDashboardStats(): Promise<DashboardStats> {
    try {
      const now = new Date()
      const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate())
      const twoMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 2, now.getDate())

      // Current period stats
      const [currentStats, previousStats] = await Promise.all([
        this.getPeriodStats(lastMonth, now),
        this.getPeriodStats(twoMonthsAgo, lastMonth)
      ])

      // Calculate growth percentages
      const revenueGrowth = this.calculateGrowth(currentStats.revenue, previousStats.revenue)
      const ordersGrowth = this.calculateGrowth(currentStats.orders, previousStats.orders)
      const customersGrowth = this.calculateGrowth(currentStats.customers, previousStats.customers)
      const productsGrowth = this.calculateGrowth(currentStats.products, previousStats.products)

      return {
        totalRevenue: currentStats.revenue,
        totalOrders: currentStats.orders,
        totalCustomers: currentStats.customers,
        totalProducts: currentStats.products,
        revenueGrowth,
        ordersGrowth,
        customersGrowth,
        productsGrowth
      }
    } catch (error) {
      console.error('Error in getDashboardStats:', error)
      // Return default stats if there's an error
      return {
        totalRevenue: 0,
        totalOrders: 0,
        totalCustomers: 0,
        totalProducts: 0,
        revenueGrowth: 0,
        ordersGrowth: 0,
        customersGrowth: 0,
        productsGrowth: 0
      }
    }
  }

  private static async getPeriodStats(startDate: Date, endDate: Date) {
    try {
      const [revenueResult, ordersCount, customersCount, productsCount] = await Promise.all([
        db.order.aggregate({
          where: {
            createdAt: { gte: startDate, lte: endDate },
            status: 'DELIVERED'
          },
          _sum: { totalAmount: true }
        }),
        db.order.count({
          where: {
            createdAt: { gte: startDate, lte: endDate }
          }
        }),
        db.customer.count({
          where: {
            createdAt: { gte: startDate, lte: endDate },
            phone: 'CUSTOMER'
          }
        }),
        db.product.count({
          where: {
            createdAt: { gte: startDate, lte: endDate },
            isActive: true
          }
        })
      ])

      // Handle Decimal conversion safely
      let revenue = Number(revenueResult._sum.totalAmount) || 0

      return {
        revenue,
        orders: ordersCount || 0,
        customers: customersCount || 0,
        products: productsCount || 0
      }
    } catch (error) {
      console.error('Error in getPeriodStats:', error)
      return {
        revenue: 0,
        orders: 0,
        customers: 0,
        products: 0
      }
    }
  }

  private static calculateGrowth(current: number, previous: number): number {
    if (previous === 0) {
      return current > 0 ? 100 : 0
    }
    const growth = ((current - previous) / previous) * 100
    // Handle edge cases
    if (!isFinite(growth)) return 0
    return growth
  }

  static async getSalesData(days = 30): Promise<SalesData[]> {
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    const salesData = await db.order.groupBy({
      by: ['createdAt'],
      where: {
        createdAt: { gte: startDate },
        status: 'DELIVERED'
      },
      _sum: {
        totalAmount: true
      },
      _count: true,
      orderBy: {
        createdAt: 'asc'
      }
    })

    // Format data for charts
    return salesData.map((item: any) => ({
      date: item.createdAt.toISOString().split('T')[0],
      revenue: Number(item._sum.totalAmount) || 0,
      orders: item._count
    }))
  }

  static async getTopProducts(limit = 10): Promise<TopProduct[]> {
    const topProductsData = await db.orderItem.groupBy({
      by: ['productId'],
      _sum: {
        quantity: true,
        totalPrice: true
      },
      orderBy: {
        _sum: {
          quantity: 'desc'
        }
      },
      take: limit
    })

    // Get product details
    const productIds = topProductsData.map((item: any) => item.productId)
    const products = await db.product.findMany({
      where: { id: { in: productIds } },
      include: {
        images: {
          where: { isPrimary: true },
          take: 1
        }
      }
    })

    return topProductsData.map((item: any) => {
      const product = products.find((p: any) => p.id === item.productId)
      return {
        id: item.productId,
        name: product?.name || 'Unknown Product',
        slug: product?.slug || '',
        totalSold: item._sum.quantity || 0,
        revenue: Number(item._sum.totalPrice) || 0,
        image: product?.images[0]?.url
      }
    })
  }

  static async getCategoryPerformance(): Promise<CategoryPerformance[]> {
    const categoryData = await db.orderItem.groupBy({
      by: ['productId'],
      _sum: {
        quantity: true,
        totalPrice: true
      }
    })

    // Get products with categories
    const productIds = categoryData.map((item: any) => item.productId)
    const products = await db.product.findMany({
      where: { id: { in: productIds } },
      include: { category: true }
    })

    // Group by category
    const categoryMap = new Map<string, { name: string; totalSold: number; revenue: number }>()

    categoryData.forEach((item: any) => {
      const product = products.find((p: any) => p.id === item.productId)
      if (product?.category) {
        const existing = categoryMap.get(product.category.id) || {
          name: product.category.name,
          totalSold: 0,
          revenue: 0
        }
        
        existing.totalSold += item._sum.quantity || 0
        existing.revenue += item._sum.totalPrice?.toNumber() || 0
        
        categoryMap.set(product.category.id, existing)
      }
    })

    const totalRevenue = Array.from(categoryMap.values()).reduce((sum, cat) => sum + cat.revenue, 0)

    return Array.from(categoryMap.entries()).map(([id, data]) => ({
      id,
      name: data.name,
      totalSold: data.totalSold,
      revenue: data.revenue,
      percentage: totalRevenue > 0 ? (data.revenue / totalRevenue) * 100 : 0
    }))
  }

  static async trackEvent(data: {
    eventType: AnalyticsEventType
    customerId?: string
    sessionId?: string
    productId?: string
    orderId?: string
    data?: any
  }) {
    return db.analyticsEvent.create({
      data: {
        eventType: data.eventType,
        customerId: data.customerId,
        sessionId: data.sessionId,
        productId: data.productId,
        orderId: data.orderId,
        data: data.data,
      }
    })
  }

  static async getRecentSales(limit = 10) {
    return db.order.findMany({
      where: {
        status: 'DELIVERED'
      },
      include: {
        customer: {
          select: {
            firstName: true,
            lastName: true,
            email: true
          }
        },
        items: {
          take: 1,
          include: {
            product: {
              select: {
                name: true,
                images: {
                  where: { isPrimary: true },
                  take: 1,
                  select: { url: true }
                }
              }
            }
          }
        }
      },
      orderBy: { deliveredAt: 'desc' },
      take: limit
    })
  }

  static async getInventoryAlerts() {
    const variants = await db.productVariant.findMany({
      where: {
        stock: {
          lte: db.productVariant.fields.lowStockThreshold
        },
        isActive: true
      },
      include: {
        product: {
          select: {
            name: true,
            slug: true,
            images: {
              where: { isPrimary: true },
              take: 1,
              select: { url: true }
            }
          }
        }
      },
      orderBy: { stock: 'asc' }
    })

    return variants.map(variant => ({
      ...variant,
      price: Number(variant.price),
      comparePrice: variant.comparePrice ? Number(variant.comparePrice) : null,
      costPrice: variant.costPrice ? Number(variant.costPrice) : null,
      weight: variant.weight ? Number(variant.weight) : null
    }))
  }
}
