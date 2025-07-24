'use client';

import { useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  IconMinus,
  IconPlus,
  IconTrash,
  IconShoppingBag,
  IconHeart,
  IconTruck,
  IconShield,
  IconArrowRight,
  IconTag
} from '@tabler/icons-react';
import { useCartStore } from '@/lib/cart-store';
import { formatPrice } from '@/lib/format';

export function CartView() {
  const { 
    items, 
    updateQuantity, 
    removeItem, 
    totalPrice,
    totalItems,
    clearCart 
  } = useCartStore();
  
  const [promoCode, setPromoCode] = useState('');
  const [promoApplied, setPromoApplied] = useState(false);
  const [promoDiscount, setPromoDiscount] = useState(0);

  const subtotal = totalPrice;
  const shipping = subtotal > 500 ? 0 : 50; // Free shipping over R500
  const tax = subtotal * 0.15; // 15% VAT
  const discount = promoApplied ? promoDiscount : 0;
  const finalTotal = subtotal + shipping + tax - discount;

  const handleQuantityChange = (id: string, newQuantity: number) => {
    if (newQuantity < 1) {
      removeItem(id);
    } else {
      updateQuantity(id, newQuantity);
    }
  };

  const handleApplyPromo = () => {
    // Mock promo code logic
    if (promoCode.toLowerCase() === 'save10') {
      setPromoApplied(true);
      setPromoDiscount(subtotal * 0.1); // 10% discount
    }
  };

  const handleMoveToWishlist = (id: string) => {
    // TODO: Implement wishlist functionality
    removeItem(id);
  };

  if (items.length === 0) {
    return (
      <div className="text-center py-16">
        <div className="w-24 h-24 mx-auto bg-gray-100 rounded-full flex items-center justify-center mb-6">
          <IconShoppingBag className="h-12 w-12 text-gray-400" />
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-4">
          Your cart is empty
        </h2>
        <p className="text-gray-600 mb-8 max-w-md mx-auto">
          Looks like you haven't added any items to your cart yet. 
          Start shopping to fill it up!
        </p>
        <Button asChild size="lg">
          <Link href="/products">
            Continue Shopping
          </Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Shopping Cart</h1>
          <p className="text-gray-600 mt-2">
            {totalItems} item{totalItems !== 1 ? 's' : ''} in your cart
          </p>
        </div>
        <Button variant="outline" onClick={clearCart}>
          Clear Cart
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Cart Items */}
        <div className="lg:col-span-2 space-y-6">
          {items.map((item) => (
            <Card key={item.id}>
              <CardContent className="p-6">
                <div className="flex space-x-4">
                  {/* Product Image */}
                  <div className="relative h-24 w-24 rounded-md overflow-hidden bg-gray-100 flex-shrink-0">
                    <Image
                      src={item.image}
                      alt={item.name}
                      fill
                      className="object-cover"
                    />
                  </div>
                  
                  {/* Product Details */}
                  <div className="flex-1 space-y-2">
                    <div className="flex justify-between">
                      <div>
                        <h3 className="font-semibold text-lg">
                          <Link
                            href={`/products/${item.productId}`}
                            className="hover:text-primary transition-colors"
                          >
                            {item.name}
                          </Link>
                        </h3>
                        <p className="text-gray-600">
                          {item.color} • {item.size}
                        </p>
                        <p className="text-sm text-gray-500">
                          SKU: {item.sku}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="font-semibold text-lg">
                          {formatPrice(item.price * item.quantity)}
                        </p>
                        <p className="text-sm text-gray-500">
                          {formatPrice(item.price)} each
                        </p>
                      </div>
                    </div>
                    
                    {/* Quantity and Actions */}
                    <div className="flex items-center justify-between pt-2">
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="outline"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => handleQuantityChange(item.id, item.quantity - 1)}
                        >
                          <IconMinus className="h-3 w-3" />
                        </Button>
                        <span className="w-12 text-center font-medium">
                          {item.quantity}
                        </span>
                        <Button
                          variant="outline"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => handleQuantityChange(item.id, item.quantity + 1)}
                        >
                          <IconPlus className="h-3 w-3" />
                        </Button>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleMoveToWishlist(item.id)}
                        >
                          <IconHeart className="mr-1 h-4 w-4" />
                          Save for Later
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => removeItem(item.id)}
                          className="text-red-600 hover:text-red-700"
                        >
                          <IconTrash className="mr-1 h-4 w-4" />
                          Remove
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Order Summary */}
        <div className="space-y-6">
          {/* Promo Code */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <IconTag className="mr-2 h-5 w-5" />
                Promo Code
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex space-x-2">
                <Input
                  placeholder="Enter promo code"
                  value={promoCode}
                  onChange={(e) => setPromoCode(e.target.value)}
                  disabled={promoApplied}
                />
                <Button 
                  onClick={handleApplyPromo}
                  disabled={!promoCode || promoApplied}
                >
                  Apply
                </Button>
              </div>
              {promoApplied && (
                <div className="flex items-center justify-between text-green-600">
                  <span className="text-sm">Promo applied: SAVE10</span>
                  <span className="font-medium">-{formatPrice(discount)}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Order Summary */}
          <Card>
            <CardHeader>
              <CardTitle>Order Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span>Subtotal ({totalItems} items)</span>
                  <span>{formatPrice(subtotal)}</span>
                </div>
                
                <div className="flex justify-between">
                  <span className="flex items-center">
                    <IconTruck className="mr-1 h-4 w-4" />
                    Shipping
                  </span>
                  <span>
                    {shipping === 0 ? (
                      <Badge variant="secondary">FREE</Badge>
                    ) : (
                      formatPrice(shipping)
                    )}
                  </span>
                </div>
                
                <div className="flex justify-between">
                  <span>VAT (15%)</span>
                  <span>{formatPrice(tax)}</span>
                </div>
                
                {promoApplied && (
                  <div className="flex justify-between text-green-600">
                    <span>Discount</span>
                    <span>-{formatPrice(discount)}</span>
                  </div>
                )}
              </div>
              
              <Separator />
              
              <div className="flex justify-between text-lg font-semibold">
                <span>Total</span>
                <span>{formatPrice(finalTotal)}</span>
              </div>
              
              {shipping === 0 && (
                <div className="flex items-center text-sm text-green-600">
                  <IconShield className="mr-1 h-4 w-4" />
                  Free shipping applied
                </div>
              )}
              
              <Button size="lg" className="w-full" asChild>
                <Link href="/checkout">
                  Proceed to Checkout
                  <IconArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              
              <Button variant="outline" size="lg" className="w-full" asChild>
                <Link href="/products">
                  Continue Shopping
                </Link>
              </Button>
            </CardContent>
          </Card>

          {/* Security Features */}
          <Card>
            <CardContent className="pt-6">
              <div className="space-y-3 text-sm text-gray-600">
                <div className="flex items-center">
                  <IconShield className="mr-2 h-4 w-4 text-green-600" />
                  Secure 256-bit SSL encryption
                </div>
                <div className="flex items-center">
                  <IconTruck className="mr-2 h-4 w-4 text-blue-600" />
                  Free delivery on orders over R500
                </div>
                <div className="flex items-center">
                  <IconHeart className="mr-2 h-4 w-4 text-red-600" />
                  30-day return policy
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
