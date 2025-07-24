import { db } from '@/lib/prisma';
import type { Customer, Address, Order, Review, AddressType } from '@prisma/client';

export type CustomerWithDetails = Customer & {
  addresses: Address[];
  orders: Order[];
  reviews: Review[];
};

export type CreateCustomerData = {
  email: string;
  firstName: string;
  lastName: string;
  imageUrl?: string;
  phone?: string;
};

export type UpdateCustomerData = {
  firstName?: string;
  lastName?: string;
  imageUrl?: string;
  phone?: string;
};

export type CreateAddressData = {
  customerId: string;
  type: AddressType;
  firstName: string;
  lastName: string;
  company?: string;
  addressLine1: string;
  addressLine2?: string;
  city: string;
  province: string;
  postalCode: string;
  country?: string;
  phone?: string;
  isDefault?: boolean;
};

export class CustomerService {
  static async createCustomer(data: CreateCustomerData): Promise<Customer> {
    return db.customer.create({ data });
  }

  static async getCustomerById(id: string): Promise<CustomerWithDetails | null> {
    return db.customer.findUnique({
      where: { id },
      include: {
        addresses: { orderBy: { isDefault: 'desc' } },
        orders: true,
        reviews: true,
      },
    });
  }

  static async updateCustomer(id: string, data: UpdateCustomerData): Promise<Customer> {
    return db.customer.update({
      where: { id },
      data,
    });
  }

  static async deleteCustomer(id: string): Promise<void> {
    await db.customer.delete({ where: { id } });
  }

  static async getCustomers({
    search,
    page = 1,
    limit = 10,
  }: {
    search?: string;
    page?: number;
    limit?: number;
  } = {}) {
    const skip = (page - 1) * limit;

    const where: import('@prisma/client').Prisma.CustomerWhereInput = {};

    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { phone: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [customers, total] = await Promise.all([
      db.customer.findMany({
        where,
        include: {
          addresses: { orderBy: { isDefault: 'desc' } },
          orders: true,
          reviews: true,
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      db.customer.count({ where }),
    ]);

    return {
      customers,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }

  static async createAddress(data: CreateAddressData): Promise<Address> {
    if (data.isDefault) {
      // Make existing default addresses false before creating new default address
      await db.address.updateMany({
        where: {
          customerId: data.customerId,
          type: data.type,
        },
        data: { isDefault: false },
      });
    }

    return db.address.create({
      data: {
        customerId: data.customerId,
        type: data.type,
        firstName: data.firstName,
        lastName: data.lastName,
        company: data.company,
        addressLine1: data.addressLine1,
        addressLine2: data.addressLine2,
        city: data.city,
        province: data.province,
        postalCode: data.postalCode,
        country: data.country || 'South Africa',
        phone: data.phone,
        isDefault: data.isDefault || false,
      },
    });
  }

  static async updateAddress(id: string, data: Partial<CreateAddressData>): Promise<Address> {
    const address = await db.address.findUnique({ where: { id } });
    if (!address) throw new Error('Address not found');

    if (data.isDefault) {
      await db.address.updateMany({
        where: {
          customerId: address.customerId,
          type: address.type,
          id: { not: id },
        },
        data: { isDefault: false },
      });
    }

    return db.address.update({
      where: { id },
      data,
    });
  }

  static async deleteAddress(id: string): Promise<void> {
    await db.address.delete({ where: { id } });
  }

  static async getCustomerAddresses(customerId: string, type?: AddressType): Promise<Address[]> {
    return db.address.findMany({
      where: {
        customerId,
        ...(type && { type }),
      },
      orderBy: { isDefault: 'desc' },
    });
  }

  static async getDefaultAddress(customerId: string, type: AddressType): Promise<Address | null> {
    return db.address.findFirst({
      where: {
        customerId,
        type,
        isDefault: true,
      },
    });
  }

  static async getCustomerStats() {
    const [totalCustomers, newCustomersThisMonth] = await Promise.all([
      db.customer.count(),
      db.customer.count({
        where: {
          createdAt: {
            gte: new Date(new Date().getFullYear(), new Date().getMonth(), 1),
          },
        },
      }),
    ]);

    return {
      totalCustomers,
      newCustomersThisMonth,
    };
  }
}

