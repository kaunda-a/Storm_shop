import { db } from '@/lib/prisma'
import type { MarqueeMessage, User, MarqueeType } from '@prisma/client'

export type MarqueeMessageWithCreator = MarqueeMessage & {
  creator: Pick<User, 'id' | 'firstName' | 'lastName' | 'email'>
}

export type CreateMarqueeData = {
  title: string
  message: string
  type?: MarqueeType
  priority?: number
  startDate?: Date
  endDate?: Date
  createdBy: string
}

export type UpdateMarqueeData = {
  title?: string
  message?: string
  type?: MarqueeType
  priority?: number
  isActive?: boolean
  startDate?: Date
  endDate?: Date
}

export class MarqueeService {
  static async getActiveMessages(): Promise<MarqueeMessageWithCreator[]> {
    const now = new Date()
    
    return db.marqueeMessage.findMany({
      where: {
        isActive: true,
        OR: [
          { startDate: null },
          { startDate: { lte: now } }
        ],
        AND: [
          {
            OR: [
              { endDate: null },
              { endDate: { gte: now } }
            ]
          }
        ]
      },
      include: {
        creator: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      },
      orderBy: [
        { priority: 'desc' },
        { createdAt: 'desc' }
      ]
    })
  }

  static async getAllMessages({
    page = 1,
    limit = 10,
    type,
    isActive
  }: {
    page?: number
    limit?: number
    type?: MarqueeType
    isActive?: boolean
  } = {}): Promise<{
    messages: MarqueeMessageWithCreator[]
    pagination: { page: number; limit: number; total: number; pages: number }
  }> {
    const skip = (page - 1) * limit

    const where: any = {}
    if (type) where.type = type
    if (isActive !== undefined) where.isActive = isActive

    const [messages, total] = await Promise.all([
      db.marqueeMessage.findMany({
        where,
        include: {
          creator: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              email: true
            }
          }
        },
        orderBy: [
          { priority: 'desc' },
          { createdAt: 'desc' }
        ],
        skip,
        take: limit
      }),
      db.marqueeMessage.count({ where })
    ])

    return {
      messages,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  }

  static async createMessage(data: CreateMarqueeData): Promise<MarqueeMessage> {
    return db.marqueeMessage.create({
      data: {
        title: data.title,
        message: data.message,
        type: data.type || 'INFO',
        priority: data.priority || 1,
        startDate: data.startDate,
        endDate: data.endDate,
        createdBy: data.createdBy
      }
    })
  }

  static async updateMessage(id: string, data: UpdateMarqueeData): Promise<MarqueeMessage> {
    return db.marqueeMessage.update({
      where: { id },
      data
    })
  }

  static async deleteMessage(id: string): Promise<void> {
    await db.marqueeMessage.delete({
      where: { id }
    })
  }

  static async getMessageById(id: string): Promise<MarqueeMessageWithCreator | null> {
    return db.marqueeMessage.findUnique({
      where: { id },
      include: {
        creator: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    })
  }

  // Utility methods for creating common message types
  static async createSystemAlert(message: string, createdBy: string, priority = 3) {
    return this.createMessage({
      title: 'System Alert',
      message,
      type: 'SYSTEM',
      priority,
      createdBy
    })
  }

  static async createInventoryAlert(productName: string, stock: number, createdBy: string) {
    return this.createMessage({
      title: 'Low Stock Alert',
      message: `${productName} is running low (${stock} units remaining)`,
      type: 'INVENTORY',
      priority: 4,
      createdBy
    })
  }

  static async createOrderAlert(orderNumber: string, amount: number, createdBy: string) {
    return this.createMessage({
      title: 'New Order',
      message: `Order #${orderNumber} received - R${amount.toFixed(2)}`,
      type: 'ORDER',
      priority: 2,
      createdBy
    })
  }

  static async createPromotionMessage(title: string, message: string, createdBy: string, endDate?: Date) {
    return this.createMessage({
      title,
      message,
      type: 'PROMOTION',
      priority: 3,
      endDate,
      createdBy
    })
  }

  // Auto-cleanup expired messages
  static async cleanupExpiredMessages(): Promise<number> {
    const now = new Date()
    
    const result = await db.marqueeMessage.deleteMany({
      where: {
        endDate: {
          lt: now
        }
      }
    })

    return result.count
  }

  // Get message statistics
  static async getMessageStats() {
    const [
      totalMessages,
      activeMessages,
      expiredMessages,
      messagesByType
    ] = await Promise.all([
      db.marqueeMessage.count(),
      db.marqueeMessage.count({ where: { isActive: true } }),
      db.marqueeMessage.count({
        where: {
          endDate: { lt: new Date() }
        }
      }),
      db.marqueeMessage.groupBy({
        by: ['type'],
        _count: true,
        orderBy: {
          _count: {
            type: 'desc'
          }
        }
      })
    ])

    return {
      totalMessages,
      activeMessages,
      expiredMessages,
      messagesByType
    }
  }
}
