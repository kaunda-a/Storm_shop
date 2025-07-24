import { db } from '@/lib/prisma'
import type { Order, OrderItem, Customer, Address, OrderStatus, PaymentStatus, ShippingStatus } from '@prisma/client'
import { Decimal } from '@prisma/client/runtime/library'

export type Payment = {
  id: string
  amount: Decimal
  status: PaymentStatus
  method: string
  processedAt: Date | null
}

export type OrderWithDetails = Order & {
  customer: Customer
  shippingAddress?: Address | null
  billingAddress?: Address | null
  items: (OrderItem & {
    product: {
      name: string
      slug: string
      images: { url: string }[]
      category?: {
        id: string
        name: string
        imageUrl: string | null
        createdAt: Date
        updatedAt: Date
        description: string | null
        isActive: boolean
        sortOrder: number
        slug: string
      } | null
      brand?: {
        id: string
        name: string
        slug: string
        logoUrl: string | null
        description: string | null
        isActive: boolean
        createdAt: Date
        updatedAt: Date
      } | null
    }
    productVariant?: {
      size: string
      color: string
      sku: string
    } | null
  })[]
  payments?: Payment[]
}

export type OrderFilters = {
  status?: OrderStatus
  paymentStatus?: PaymentStatus
  shippingStatus?: ShippingStatus
  customerId?: string
  dateFrom?: Date
  dateTo?: Date
  search?: string
}

export class OrderService {
  static async getOrders({
    filters = {},
    page = 1,
    limit = 10
  }: {
    filters?: OrderFilters
    page?: number
    limit?: number
  } = {}) {
    const skip = (page - 1) * limit

    const where: any = {}

    // Apply filters
    if (filters.status) where.status = filters.status
    if (filters.paymentStatus) where.paymentStatus = filters.paymentStatus
    if (filters.shippingStatus) where.shippingStatus = filters.shippingStatus
    if (filters.customerId) where.customerId = filters.customerId

    if (filters.dateFrom || filters.dateTo) {
      where.createdAt = {
        ...(filters.dateFrom && { gte: filters.dateFrom }),
        ...(filters.dateTo && { lte: filters.dateTo })
      }
    }

    if (filters.search) {
      where.OR = [
        { orderNumber: { contains: filters.search, mode: 'insensitive' } },
        { trackingNumber: { contains: filters.search, mode: 'insensitive' } },
        { customer: { email: { contains: filters.search, mode: 'insensitive' } } }
      ]
    }

    const [orders, total] = await Promise.all([
      db.order.findMany({
        where,
        include: {
          customer: true,
          shippingAddress: true,
          billingAddress: true,
          items: {
            include: {
              product: {
                select: {
                  name: true,
                  slug: true,
                  images: {
                    where: { isPrimary: true },
                    select: { url: true },
                    take: 1
                  }
                }
              },
              productVariant: {
                select: {
                  size: true,
                  color: true,
                  sku: true
                }
              }
            }
          },
          payments: {
            select: {
              id: true,
              amount: true,
              status: true,
              method: true,
              processedAt: true
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit
      }),
      db.order.count({ where })
    ])

    return {
      orders,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  }

  static async getOrderById(id: string): Promise<OrderWithDetails | null> {
    return db.order.findUnique({
      where: { id },
      include: {
        customer: true,
        shippingAddress: true,
        billingAddress: true,
        items: {
          include: {
            product: {
              select: {
                name: true,
                slug: true,
                images: {
                  where: { isPrimary: true },
                  select: { url: true },
                  take: 1
                }
              }
            },
            productVariant: {
              select: {
                size: true,
                color: true,
                sku: true
              }
            }
          }
        },
        payments: {
          select: {
            id: true,
            amount: true,
            status: true,
            method: true,
            processedAt: true
          }
        }
      }
    })
  }

  static async getOrderByNumber(orderNumber: string): Promise<OrderWithDetails | null> {
    return db.order.findUnique({
      where: { orderNumber },
      include: {
        customer: true,
        shippingAddress: true,
        billingAddress: true,
        items: {
          include: {
            product: {
              select: {
                name: true,
                slug: true,
                images: {
                  where: { isPrimary: true },
                  select: { url: true },
                  take: 1
                }
              }
            },
            productVariant: {
              select: {
                size: true,
                color: true,
                sku: true
              }
            }
          }
        },
        payments: true
      }
    })
  }

  static async updateOrderStatus(orderId: string, status: OrderStatus) {
    return db.order.update({
      where: { id: orderId },
      data: { 
        status,
        ...(status === 'SHIPPED' && { shippedAt: new Date() }),
        ...(status === 'DELIVERED' && { deliveredAt: new Date() })
      }
    })
  }

  static async updateShippingStatus(orderId: string, status: ShippingStatus, trackingNumber?: string) {
    return db.order.update({
      where: { id: orderId },
      data: {
        shippingStatus: status,
        ...(trackingNumber && { trackingNumber }),
        ...(status === 'SHIPPED' && { shippedAt: new Date() }),
        ...(status === 'DELIVERED' && { deliveredAt: new Date() })
      }
    })
  }

  static async updateOrder(orderId: string, data: {
    status?: OrderStatus
    paymentStatus?: PaymentStatus
    shippingStatus?: ShippingStatus
    notes?: string
    trackingNumber?: string
    shippedAt?: Date
    deliveredAt?: Date
  }) {
    return db.order.update({
      where: { id: orderId },
      data: {
        ...data,
        // Auto-set timestamps based on status changes
        ...(data.status === 'SHIPPED' && !data.shippedAt && { shippedAt: new Date() }),
        ...(data.status === 'DELIVERED' && !data.deliveredAt && { deliveredAt: new Date() }),
        ...(data.shippingStatus === 'SHIPPED' && !data.shippedAt && { shippedAt: new Date() }),
        ...(data.shippingStatus === 'DELIVERED' && !data.deliveredAt && { deliveredAt: new Date() })
      },
      include: {
        customer: true,
        shippingAddress: true,
        billingAddress: true,
        items: {
          include: {
            product: {
              select: {
                name: true,
                slug: true,
                images: {
                  where: { isPrimary: true },
                  select: { url: true },
                  take: 1
                },
                category: {
                  select: {
                    id: true,
                    name: true,
                    slug: true,
                    imageUrl: true,
                    description: true,
                    isActive: true,
                    sortOrder: true,
                    createdAt: true,
                    updatedAt: true
                  }
                },
                brand: {
                  select: {
                    id: true,
                    name: true,
                    slug: true,
                    logoUrl: true,
                    description: true,
                    isActive: true,
                    createdAt: true,
                    updatedAt: true
                  }
                }
              }
            },
            productVariant: {
              select: {
                size: true,
                color: true,
                sku: true
              }
            }
          }
        },
        payments: {
          select: {
            id: true,
            amount: true,
            status: true,
            method: true,
            processedAt: true
          }
        }
      }
    })
  }

  static async getOrderStats() {
    const [
      totalOrders,
      pendingOrders,
      completedOrders,
      totalRevenue,
      recentOrders
    ] = await Promise.all([
      db.order.count(),
      db.order.count({ where: { status: 'PENDING' } }),
      db.order.count({ where: { status: 'DELIVERED' } }),
      db.order.aggregate({
        where: { status: 'DELIVERED' },
        _sum: { totalAmount: true }
      }),
      db.order.findMany({
        take: 5,
        orderBy: { createdAt: 'desc' },
        include: {
          customer: { select: { firstName: true, lastName: true, email: true } },
          items: {
            take: 1,
            include: {
              product: { select: { name: true } }
            }
          }
        }
      })
    ])

    return {
      totalOrders,
      pendingOrders,
      completedOrders,
      totalRevenue: totalRevenue._sum.totalAmount || 0,
      recentOrders
    }
  }

  static async getDailySales(days = 30) {
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    return db.order.groupBy({
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
  }

  static async getTopProducts(limit = 10) {
    return db.orderItem.groupBy({
      by: ['productId'],
      _sum: {
        quantity: true,
        totalPrice: true
      },
      _count: true,
      orderBy: {
        _sum: {
          quantity: 'desc'
        }
      },
      take: limit
    })
  }
}

