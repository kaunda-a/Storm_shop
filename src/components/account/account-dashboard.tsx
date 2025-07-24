import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  IconPackage, 
  IconHeart, 
  IconUser, 
  IconMapPin,
  IconCreditCard,
  IconBell,
  IconShield,
  IconArrowRight,
  IconTruck,
  IconCheck
} from '@tabler/icons-react';
import { db } from '@/lib/prisma';
import { formatPrice } from '@/lib/format';

interface AccountDashboardProps {
  customerId: string;
}

export async function AccountDashboard({ customerId }: AccountDashboardProps) {
  try {
    // Get customer data with recent orders
    const customer = await db.customer.findUnique({
      where: { id: customerId },
      include: {
        orders: {
          take: 3,
          orderBy: { createdAt: 'desc' },
          include: {
            items: {
              take: 1,
              include: {
                product: {
                  include: {
                    images: {
                      where: { isPrimary: true },
                      take: 1
                    }
                  }
                }
              }
            }
          }
        },
        _count: {
          select: {
            orders: true,
            // wishlistItems: true, // Uncomment when wishlist is implemented
          }
        }
      }
    });

    if (!customer) {
      return (
        <div className="text-center py-12">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Account not found
          </h3>
          <p className="text-gray-600">
            Unable to load your account information.
          </p>
        </div>
      );
    }

    const recentOrders = customer.orders;
    const totalOrders = customer._count.orders;
    // const wishlistCount = customer._count.wishlistItems || 0;

    return (
      <div className="space-y-8">
        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <IconPackage className="h-6 w-6 text-blue-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Orders</p>
                  <p className="text-2xl font-bold text-gray-900">{totalOrders}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="p-2 bg-red-100 rounded-lg">
                  <IconHeart className="h-6 w-6 text-red-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Wishlist Items</p>
                  <p className="text-2xl font-bold text-gray-900">0</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="p-2 bg-green-100 rounded-lg">
                  <IconShield className="h-6 w-6 text-green-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Account Status</p>
                  <p className="text-2xl font-bold text-gray-900">Active</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Recent Orders */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Recent Orders</CardTitle>
                <Button variant="outline" size="sm" asChild>
                  <Link href="/orders">
                    View All
                    <IconArrowRight className="ml-2 h-4 w-4" />
                  </Link>
                </Button>
              </CardHeader>
              <CardContent>
                {recentOrders.length > 0 ? (
                  <div className="space-y-4">
                    {recentOrders.map((order: any) => (
                      <div key={order.id} className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center space-x-4">
                          <div className="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                            {order.items[0]?.product.images[0] ? (
                              <img
                                src={order.items[0].product.images[0].url}
                                alt={order.items[0].product.name}
                                className="w-full h-full object-cover rounded-lg"
                              />
                            ) : (
                              <IconPackage className="h-6 w-6 text-gray-400" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium text-gray-900">
                              Order #{order.orderNumber}
                            </p>
                            <p className="text-sm text-gray-600">
                              {new Date(order.createdAt).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="font-medium text-gray-900">
                            {formatPrice(Number(order.totalAmount))}
                          </p>
                          <Badge variant={order.status === 'DELIVERED' ? 'default' : 'secondary'}>
                            {order.status === 'DELIVERED' && <IconCheck className="mr-1 h-3 w-3" />}
                            {order.status === 'SHIPPED' && <IconTruck className="mr-1 h-3 w-3" />}
                            {order.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <IconPackage className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-600">No orders yet</p>
                    <Button asChild className="mt-4">
                      <Link href="/products">Start Shopping</Link>
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Quick Actions */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button variant="outline" className="w-full justify-start" asChild>
                  <Link href="/account/profile">
                    <IconUser className="mr-2 h-4 w-4" />
                    Edit Profile
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start" asChild>
                  <Link href="/account/addresses">
                    <IconMapPin className="mr-2 h-4 w-4" />
                    Manage Addresses
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start" asChild>
                  <Link href="/account/payment">
                    <IconCreditCard className="mr-2 h-4 w-4" />
                    Payment Methods
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start" asChild>
                  <Link href="/wishlist">
                    <IconHeart className="mr-2 h-4 w-4" />
                    My Wishlist
                  </Link>
                </Button>
                <Button variant="outline" className="w-full justify-start" asChild>
                  <Link href="/account/notifications">
                    <IconBell className="mr-2 h-4 w-4" />
                    Notifications
                  </Link>
                </Button>
              </CardContent>
            </Card>

            {/* Account Info */}
            <Card>
              <CardHeader>
                <CardTitle>Account Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-sm font-medium text-gray-600">Name</p>
                  <p className="text-gray-900">{customer.firstName} {customer.lastName}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Email</p>
                  <p className="text-gray-900">{customer.email}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-600">Member Since</p>
                  <p className="text-gray-900">
                    {new Date(customer.createdAt).toLocaleDateString('en-ZA', {
                      year: 'numeric',
                      month: 'long'
                    })}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  } catch (error) {
    console.error('Error loading account dashboard:', error);
    return (
      <div className="text-center py-12">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">
          Error loading account information
        </h3>
        <p className="text-gray-600">
          Please try again later.
        </p>
      </div>
    );
  }
}
