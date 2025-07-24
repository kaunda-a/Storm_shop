import { db } from '@/lib/prisma'
import type { Billboard, User, BillboardType, BillboardPosition } from '@prisma/client'

export type BillboardWithCreator = Billboard & {
  creator: Pick<User, 'id' | 'firstName' | 'lastName' | 'email'>
}

export type CreateBillboardData = {
  title: string
  description?: string
  imageUrl?: string
  videoUrl?: string
  linkUrl?: string
  linkText?: string
  type?: BillboardType
  position?: BillboardPosition
  isActive?: boolean
  startDate?: Date
  endDate?: Date
  sortOrder?: number
  createdBy: string
}

export type UpdateBillboardData = {
  title?: string
  description?: string
  imageUrl?: string
  videoUrl?: string
  linkUrl?: string
  linkText?: string
  type?: BillboardType
  position?: BillboardPosition
  isActive?: boolean
  startDate?: Date
  endDate?: Date
  sortOrder?: number
}

export class BillboardService {
  static async getActiveBillboards(position?: BillboardPosition): Promise<BillboardWithCreator[]> {
    const now = new Date()
    
    const where: any = {
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
    }

    if (position) {
      where.position = position
    }

    return db.billboard.findMany({
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
        { sortOrder: 'asc' },
        { createdAt: 'desc' }
      ]
    })
  }

  static async getAllBillboards({
    page = 1,
    limit = 10,
    type,
    position,
    isActive
  }: {
    page?: number
    limit?: number
    type?: BillboardType
    position?: BillboardPosition
    isActive?: boolean
  } = {}): Promise<{
    billboards: BillboardWithCreator[]
    pagination: { page: number; limit: number; total: number; pages: number }
  }> {
    const skip = (page - 1) * limit

    const where: any = {}
    if (type) where.type = type
    if (position) where.position = position
    if (isActive !== undefined) where.isActive = isActive

    const [billboards, total] = await Promise.all([
      db.billboard.findMany({
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
          { sortOrder: 'asc' },
          { createdAt: 'desc' }
        ],
        skip,
        take: limit
      }),
      db.billboard.count({ where })
    ])

    return {
      billboards,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    }
  }

  static async createBillboard(data: CreateBillboardData): Promise<Billboard> {
    return db.billboard.create({
      data: {
        title: data.title,
        description: data.description,
        imageUrl: data.imageUrl,
        videoUrl: data.videoUrl,
        linkUrl: data.linkUrl,
        linkText: data.linkText,
        type: data.type || 'PROMOTIONAL',
        position: data.position || 'HEADER',
        isActive: data.isActive !== undefined ? data.isActive : true,
        startDate: data.startDate,
        endDate: data.endDate,
        sortOrder: data.sortOrder || 0,
        createdBy: data.createdBy
      }
    })
  }

  static async updateBillboard(id: string, data: UpdateBillboardData): Promise<Billboard> {
    return db.billboard.update({
      where: { id },
      data
    })
  }

  static async deleteBillboard(id: string): Promise<void> {
    await db.billboard.delete({
      where: { id }
    })
  }

  static async getBillboardById(id: string): Promise<BillboardWithCreator | null> {
    return db.billboard.findUnique({
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

  static async updateSortOrder(billboardIds: string[]): Promise<void> {
    const updates = billboardIds.map((id, index) =>
      db.billboard.update({
        where: { id },
        data: { sortOrder: index }
      })
    )

    await Promise.all(updates)
  }

  // Utility methods for creating common billboard types
  static async createPromotionalBanner(
    title: string,
    description: string,
    imageUrl: string,
    linkUrl: string,
    createdBy: string,
    endDate?: Date
  ) {
    return this.createBillboard({
      title,
      description,
      imageUrl,
      linkUrl,
      linkText: 'Shop Now',
      type: 'PROMOTIONAL',
      position: 'HEADER',
      endDate,
      createdBy
    })
  }

  static async createProductLaunch(
    title: string,
    description: string,
    imageUrl: string,
    productUrl: string,
    createdBy: string
  ) {
    return this.createBillboard({
      title,
      description,
      imageUrl,
      linkUrl: productUrl,
      linkText: 'View Product',
      type: 'PRODUCT_LAUNCH',
      position: 'DASHBOARD_TOP',
      createdBy
    })
  }

  static async createSeasonalCampaign(
    title: string,
    description: string,
    imageUrl: string,
    createdBy: string,
    startDate: Date,
    endDate: Date
  ) {
    return this.createBillboard({
      title,
      description,
      imageUrl,
      type: 'SEASONAL',
      position: 'HEADER',
      startDate,
      endDate,
      createdBy
    })
  }

  // Auto-cleanup expired billboards
  static async cleanupExpiredBillboards(): Promise<number> {
    const now = new Date()
    
    const result = await db.billboard.deleteMany({
      where: {
        endDate: {
          lt: now
        }
      }
    })

    return result.count
  }

  // Get billboard statistics
  static async getBillboardStats() {
    const [
      totalBillboards,
      activeBillboards,
      expiredBillboards,
      billboardsByType,
      billboardsByPosition
    ] = await Promise.all([
      db.billboard.count(),
      db.billboard.count({ where: { isActive: true } }),
      db.billboard.count({
        where: {
          endDate: { lt: new Date() }
        }
      }),
      db.billboard.groupBy({
        by: ['type'],
        _count: true,
        orderBy: {
          _count: {
            type: 'desc'
          }
        }
      }),
      db.billboard.groupBy({
        by: ['position'],
        _count: true,
        orderBy: {
          _count: {
            position: 'desc'
          }
        }
      })
    ])

    return {
      totalBillboards,
      activeBillboards,
      expiredBillboards,
      billboardsByType,
      billboardsByPosition
    }
  }
}
