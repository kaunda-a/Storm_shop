// Export all services
export * from './products'
export * from './product-variants'
export * from './orders'
export * from './analytics'
export * from './marquee'
export * from './billboard'
export * from './customer'
export * from './users'

// Re-export commonly used types
export type {
  ProductWithDetails,
  ProductFilters,
  ProductSort
} from './products'

export type {
  CreateVariantData,
  UpdateVariantData,
  BulkVariantCreate,
  BulkVariantUpdate,
  SizeColorMatrix,
  VariantTemplate
} from './product-variants'

export type {
  ProductStatus,
  OrderStatus,
  PaymentStatus,
  ShippingStatus,
  UserRole,
  AddressType,
  AnalyticsEventType,
  MarqueeType,
  BillboardPosition,
  BillboardType
} from '@prisma/client'

export type {
  OrderWithDetails,
  OrderFilters
} from './orders'

export {
  AnalyticsService
} from './analytics'

export type {
  DashboardStats,
  SalesData,
  TopProduct,
  CategoryPerformance
} from './analytics'

export type {
  MarqueeMessageWithCreator,
  CreateMarqueeData,
  UpdateMarqueeData
} from './marquee'

export type {
  BillboardWithCreator,
  CreateBillboardData,
  UpdateBillboardData
} from './billboard'

export type {
  CustomerWithDetails,
  CreateCustomerData,
  UpdateCustomerData,
  CreateAddressData
} from './customer';

export type {
  UserWithDetails,
  CreateUserData,
  UpdateUserData
} from './users'
