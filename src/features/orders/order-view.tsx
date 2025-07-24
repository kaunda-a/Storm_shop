'use client';

import { useEffect, useState } from 'react';
import { notFound } from 'next/navigation';
import { toast } from 'sonner';
import { OrderDetails } from './order-details';
import { OrderWithDetails } from '@/lib/services';

type TOrderViewPageProps = {
  orderId: string;
};

export function OrderViewPage({
  orderId
}: TOrderViewPageProps) {
  const [order, setOrder] = useState<OrderWithDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    async function fetchOrder() {
      if (orderId === 'new') {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const response = await fetch(`/api/orders/${orderId}`, {
          cache: 'no-store',
          headers: {
            'Content-Type': 'application/json',
          },
        });

        if (!response.ok) {
          if (response.status === 404) {
            setError(true);
            toast.error('Order not found');
            return;
          }
          throw new Error(`Failed to fetch order: ${response.status}`);
        }

        const orderData = await response.json();
        setOrder(orderData);
      } catch (error) {
        console.error('Error fetching order:', error);
        setError(true);
        toast.error('Failed to load order data');
      } finally {
        setLoading(false);
      }
    }

    fetchOrder();
  }, [orderId]);

  if (error) {
    notFound();
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  if (!order && orderId !== 'new') {
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

  // For customer-facing shop, we only show order details (no editing)
  // If this was admin, we'd show OrderForm for editing
  return <OrderDetails orderId={orderId} />;
}
