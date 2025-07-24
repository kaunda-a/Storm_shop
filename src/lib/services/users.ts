import { db } from '@/lib/prisma';
import { User, UserRole } from '@prisma/client';

// User role hierarchy and permissions
export const USER_ROLES = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  ADMIN: 'ADMIN',
  MANAGER: 'MANAGER',
  STAFF: 'STAFF'
} as const;

// Role hierarchy (higher number = more permissions)
export const ROLE_HIERARCHY = {
  [USER_ROLES.STAFF]: 1,
  [USER_ROLES.MANAGER]: 2,
  [USER_ROLES.ADMIN]: 3,
  [USER_ROLES.SUPER_ADMIN]: 4
} as const;

// Role display names
export const ROLE_DISPLAY_NAMES = {
  [USER_ROLES.SUPER_ADMIN]: 'Super Administrator',
  [USER_ROLES.ADMIN]: 'Administrator',
  [USER_ROLES.MANAGER]: 'Manager',
  [USER_ROLES.STAFF]: 'Staff Member'
} as const;

// Role descriptions
export const ROLE_DESCRIPTIONS = {
  [USER_ROLES.SUPER_ADMIN]: 'Full system access with user management capabilities',
  [USER_ROLES.ADMIN]: 'Administrative access to most system features',
  [USER_ROLES.MANAGER]: 'Management access to products, orders, and customers',
  [USER_ROLES.STAFF]: 'Basic access to view and manage assigned tasks'
} as const;

// Permission structure type
type PermissionActions = {
  create: boolean;
  read: boolean;
  update: boolean;
  delete: boolean;
};

type ResourcePermissions = {
  users: PermissionActions;
  products: PermissionActions;
  orders: PermissionActions;
  customers: PermissionActions;
  billboards: PermissionActions;
  marquee: PermissionActions;
  analytics: { read: boolean };
  settings: { read: boolean; update: boolean };
};

// Permissions for each role
export const ROLE_PERMISSIONS: Record<UserRole, ResourcePermissions> = {
  [USER_ROLES.SUPER_ADMIN]: {
    users: { create: true, read: true, update: true, delete: true },
    products: { create: true, read: true, update: true, delete: true },
    orders: { create: true, read: true, update: true, delete: true },
    customers: { create: true, read: true, update: true, delete: true },
    billboards: { create: true, read: true, update: true, delete: true },
    marquee: { create: true, read: true, update: true, delete: true },
    analytics: { read: true },
    settings: { read: true, update: true }
  },
  [USER_ROLES.ADMIN]: {
    users: { create: false, read: true, update: false, delete: false },
    products: { create: true, read: true, update: true, delete: true },
    orders: { create: true, read: true, update: true, delete: false },
    customers: { create: true, read: true, update: true, delete: false },
    billboards: { create: true, read: true, update: true, delete: true },
    marquee: { create: true, read: true, update: true, delete: true },
    analytics: { read: true },
    settings: { read: true, update: false }
  },
  [USER_ROLES.MANAGER]: {
    users: { create: false, read: false, update: false, delete: false },
    products: { create: true, read: true, update: true, delete: false },
    orders: { create: false, read: true, update: true, delete: false },
    customers: { create: false, read: true, update: true, delete: false },
    billboards: { create: false, read: true, update: false, delete: false },
    marquee: { create: false, read: true, update: false, delete: false },
    analytics: { read: true },
    settings: { read: false, update: false }
  },
  [USER_ROLES.STAFF]: {
    users: { create: false, read: false, update: false, delete: false },
    products: { create: false, read: true, update: false, delete: false },
    orders: { create: false, read: true, update: false, delete: false },
    customers: { create: false, read: true, update: false, delete: false },
    billboards: { create: false, read: true, update: false, delete: false },
    marquee: { create: false, read: true, update: false, delete: false },
    analytics: { read: false },
    settings: { read: false, update: false }
  }
} as const;

// Helper functions
export function hasPermission(
  userRole: UserRole,
  resource: keyof ResourcePermissions,
  action: 'create' | 'read' | 'update' | 'delete'
): boolean {
  const permissions = ROLE_PERMISSIONS[userRole];
  const resourcePermissions = permissions?.[resource];
  if (!resourcePermissions) return false;

  // Handle special cases for analytics and settings
  if (resource === 'analytics') {
    return action === 'read' && (resourcePermissions as any).read;
  }

  if (resource === 'settings') {
    return (action === 'read' || action === 'update') && (resourcePermissions as any)[action];
  }

  // Handle standard CRUD permissions
  return (resourcePermissions as PermissionActions)[action] ?? false;
}

export function canManageUser(currentUserRole: UserRole, targetUserRole: UserRole): boolean {
  // Super admins can manage anyone
  if (currentUserRole === USER_ROLES.SUPER_ADMIN) return true;

  // Users can only manage users with lower hierarchy
  return ROLE_HIERARCHY[currentUserRole] > ROLE_HIERARCHY[targetUserRole];
}

export function getAvailableRoles(currentUserRole: UserRole): UserRole[] {
  const currentLevel = ROLE_HIERARCHY[currentUserRole];

  return Object.entries(ROLE_HIERARCHY)
    .filter(([_, level]) => level < currentLevel)
    .map(([role]) => role as UserRole);
}

export function getRoleColor(role: UserRole): string {
  switch (role) {
    case USER_ROLES.SUPER_ADMIN:
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
    case USER_ROLES.ADMIN:
      return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200';
    case USER_ROLES.MANAGER:
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
    case USER_ROLES.STAFF:
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
    default:
      return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
  }
}

export function formatUserName(firstName?: string | null, lastName?: string | null): string {
  if (!firstName && !lastName) return 'Unknown User';
  return `${firstName || ''} ${lastName || ''}`.trim();
}

export function getUserInitials(firstName?: string | null, lastName?: string | null): string {
  const first = firstName?.charAt(0)?.toUpperCase() || '';
  const last = lastName?.charAt(0)?.toUpperCase() || '';
  return first + last || 'U';
}

export type UserWithDetails = User & {
  _count?: {
    billboards?: number;
    marqueeMessages?: number;
  };
};

export type CreateUserData = {
  firstName: string;
  lastName: string;
  email: string;
  role: UserRole;
  imageUrl?: string;
};

export type UpdateUserData = {
  firstName?: string;
  lastName?: string;
  email?: string;
  imageUrl?: string;
  role?: UserRole;
};

export const UserService = {
  async getUserById(id: string): Promise<UserWithDetails | null> {
    return db.user.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            billboards: true,
            marqueeMessages: true,
          },
        },
      },
    });
  },

  async getUserByEmail(email: string): Promise<UserWithDetails | null> {
    return db.user.findUnique({
      where: { email },
      include: {
        _count: {
          select: {
            billboards: true,
            marqueeMessages: true,
          },
        },
      },
    });
  },

  async getUsers({
    search,
    role,
    page = 1,
    limit = 10,
  }: {
    search?: string;
    role?: UserRole;
    page?: number;
    limit?: number;
  } = {}) {
    const skip = (page - 1) * limit;

    const where: any = {};

    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
      ];
    }

    if (role) {
      where.role = role;
    }

    const [users, total] = await Promise.all([
      db.user.findMany({
        where,
        include: {
          _count: {
            select: {
              billboards: true,
              marqueeMessages: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      db.user.count({ where }),
    ]);

    return {
      users,
      total,
      pages: Math.ceil(total / limit),
      currentPage: page,
    };
  },

  async createUser(data: CreateUserData): Promise<UserWithDetails> {
    return db.user.create({
      data: {
        ...data,
        password: null, // No password for OAuth-only users
      },
      include: {
        _count: {
          select: {
            billboards: true,
            marqueeMessages: true,
          },
        },
      },
    });
  },

  async updateUser(id: string, data: UpdateUserData): Promise<UserWithDetails> {
    return db.user.update({
      where: { id },
      data: data,
      include: {
        _count: {
          select: {
            billboards: true,
            marqueeMessages: true,
          },
        },
      },
    });
  },

  async deleteUser(id: string): Promise<void> {
    await db.user.delete({ where: { id } });
  },

  async getUserStats() {
    const [totalUsers, usersByRole] = await Promise.all([
      db.user.count(),
      db.user.groupBy({
        by: ['role'],
        _count: {
          role: true,
        },
      }),
    ]);

    return {
      totalUsers,
      usersByRole: usersByRole.reduce((acc, item) => {
        acc[item.role] = item._count.role;
        return acc;
      }, {} as Record<UserRole, number>),
    };
  },
};

