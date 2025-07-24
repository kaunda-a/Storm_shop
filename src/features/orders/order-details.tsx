import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { 
  IconPackage, 
  IconTruck, 
  IconCheck, 
  IconClock, 
  IconMapPin,
  IconCreditCard,
  IconReceipt,
  IconDownload
} from '@tabler/icons-react';
import { db } from '@/lib/prisma';
import { formatPrice } from '@/lib/format';

interface OrderDetailsProps {
  orderId: string;
}

const statusConfig = {
  PENDING: { label: 'Pending', color: 'bg-yellow-100 text-yellow-800', icon: IconClock },
  CONFIRMED: { label: 'Confirmed', color: 'bg-blue-100 text-blue-800', icon: IconPackage },
  PROCESSING: { label: 'Processing', color: 'bg-purple-100 text-purple-800', icon: IconPackage },
  SHIPPED: { label: 'Shipped', color: 'bg-indigo-100 text-indigo-800', icon: IconTruck },
  DELIVERED: { label: 'Delivered', color: 'bg-green-100 text-green-800', icon: IconCheck },
  CANCELLED: { label: 'Cancelled', color: 'bg-red-100 text-red-800', icon: IconClock },
};

export async function OrderDetails({ orderId }: OrderDetailsProps) {
  try {
    const order = await db.order.findUnique({
      where: { id: orderId },
      include: {
        items: {
          include: {
            product: {
              include: {
                images: {
                  where: { isPrimary: true },
                  take: 1
                },
                brand: true,
                category: true
              }
            }
          }
        },
        customer: {
          select: {
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    if (!order) {
      return (
        <div className="text-center py-12">
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            Order not found
          </h3>
          <p className="text-gray-600">
            The order you're looking for doesn't exist or you don't have permission to view it.
          </p>
        </div>
      );
    }

    const statusInfo = statusConfig[order.status as keyof typeof statusConfig];
    const StatusIcon = statusInfo.icon;

    return (
      <div className="space-y-8">
        {/* Order Header */}
        <div className="bg-white rounded-lg border p-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">
                Order #{order.orderNumber}
              </h1>
              <p className="text-gray-600 mt-1">
                Placed on {new Date(order.createdAt).toLocaleDateString('en-ZA', {
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit'
                })}
              </p>
            </div>
            <div className="flex items-center gap-4">
              <Badge className={`${statusInfo.color} text-sm px-3 py-1`}>
                <StatusIcon className="mr-2 h-4 w-4" />
                {statusInfo.label}
              </Badge>
              <Button variant="outline" size="sm">
                <IconDownload className="mr-2 h-4 w-4" />
                Download Invoice
              </Button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Order Items */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <IconPackage className="mr-2 h-5 w-5" />
                  Order Items ({order.items.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {order.items.map((item) => (
                  <div key={item.id} className="flex items-center space-x-4 p-4 border rounded-lg">
                    <div className="w-20 h-20 bg-gray-100 rounded-lg flex items-center justify-center overflow-hidden">
                      {item.product.images[0] ? (
                        <img
                          src={item.product.images[0].url}
                          alt={item.product.name}
                          className="w-full h-full object-cover"
                        />
                      ) : (
                        <IconPackage className="h-8 w-8 text-gray-400" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-gray-900">
                        <Link 
                          href={`/products/${item.product.id}`}
                          className="hover:text-primary transition-colors"
                        >
                          {item.product.name}
                        </Link>
                      </h3>
                      <p className="text-sm text-gray-600">
                        {item.product.brand.name} • {item.product.category.name}
                      </p>
                      <p className="text-sm text-gray-600">
                        {(item as any).productVariant?.color || 'N/A'} • {(item as any).productVariant?.size || 'N/A'} • Qty: {item.quantity}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="font-semibold text-gray-900">
                        {formatPrice(Number(item.unitPrice) * item.quantity)}
                      </p>
                      <p className="text-sm text-gray-600">
                        {formatPrice(Number(item.unitPrice))} each
                      </p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Order Summary & Details */}
          <div className="space-y-6">
            {/* Order Summary */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <IconReceipt className="mr-2 h-5 w-5" />
                  Order Summary
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex justify-between">
                  <span>Subtotal</span>
                  <span>{formatPrice(Number(order.totalAmount))}</span>
                </div>
                <div className="flex justify-between">
                  <span>Shipping</span>
                  <span>{formatPrice(Number(order.shippingAmount))}</span>
                </div>
                <div className="flex justify-between">
                  <span>Tax</span>
                  <span>{formatPrice(Number(order.taxAmount))}</span>
                </div>
                <Separator />
                <div className="flex justify-between font-semibold text-lg">
                  <span>Total</span>
                  <span>{formatPrice(Number(order.totalAmount))}</span>
                </div>
              </CardContent>
            </Card>

            {/* Shipping Address */}
            {(order as any).shippingAddress && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <IconMapPin className="mr-2 h-5 w-5" />
                    Shipping Address
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-sm space-y-1">
                    <p className="font-medium">
                      {(order as any).shippingAddress.firstName} {(order as any).shippingAddress.lastName}
                    </p>
                    {(order as any).shippingAddress.company && (
                      <p>{(order as any).shippingAddress.company}</p>
                    )}
                    <p>{(order as any).shippingAddress.address1}</p>
                    {(order as any).shippingAddress.address2 && (
                      <p>{(order as any).shippingAddress.address2}</p>
                    )}
                    <p>
                      {(order as any).shippingAddress.city}, {(order as any).shippingAddress.province} {(order as any).shippingAddress.postalCode}
                    </p>
                    <p>{(order as any).shippingAddress.country}</p>
                    {(order as any).shippingAddress.phone && (
                      <p className="mt-2">Phone: {(order as any).shippingAddress.phone}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Payment Information */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <IconCreditCard className="mr-2 h-5 w-5" />
                  Payment Information
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-sm space-y-2">
                  <div className="flex justify-between">
                    <span>Payment Method</span>
                    <span className="capitalize">
                      {(order as any).payments?.[0]?.method || 'Not specified'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Payment Status</span>
                    <Badge variant={order.paymentStatus === 'COMPLETED' ? 'default' : 'secondary'}>
                      {order.paymentStatus}
                    </Badge>
                  </div>
                  {(order as any).payments?.[0]?.id && (
                    <div className="flex justify-between">
                      <span>Payment ID</span>
                      <span className="font-mono text-xs">{(order as any).payments[0].id}</span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  } catch (error) {
    console.error('Error loading order details:', error);
    return (
      <div className="text-center py-12">
        <h3 className="text-lg font-semibold text-gray-900 mb-2">
          Error loading order details
        </h3>
        <p className="text-gray-600">
          Please try again later.
        </p>
      </div>
    );
  }
}
