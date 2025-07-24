'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useSession, signOut } from 'next-auth/react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  IconChevronDown,
  IconUser,
  IconPackage,
  IconHeart,
  IconLogout,
  IconMapPin,
  IconPhone,
  IconHelp
} from '@tabler/icons-react';

interface NavigationItem {
  name: string;
  href: string;
  featured?: Array<{
    name: string;
    href: string;
    slug: string;
  }>;
}

interface MobileMenuProps {
  navigation: NavigationItem[];
  onClose: () => void;
}

export function MobileMenu({ navigation, onClose }: MobileMenuProps) {
  const { data: session } = useSession();
  const [openItems, setOpenItems] = useState<string[]>([]);

  const toggleItem = (itemName: string) => {
    setOpenItems(prev => 
      prev.includes(itemName) 
        ? prev.filter(name => name !== itemName)
        : [...prev, itemName]
    );
  };

  const handleLinkClick = () => {
    onClose();
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="p-4 border-b">
        <div className="flex items-center space-x-2">
          <div className="bg-slate-900 text-white p-2 rounded-lg">
            <span className="font-bold text-lg">MF</span>
          </div>
          <div>
            <span className="font-bold text-xl text-slate-900">Mzansi</span>
            <span className="font-light text-xl text-slate-600">Footwear</span>
          </div>
        </div>
      </div>

      {/* User Section */}
      {session ? (
        <div className="p-4 border-b">
          <div className="flex items-center space-x-3 mb-4">
            <Avatar className="h-10 w-10">
              <AvatarImage src={session.user?.image || ''} />
              <AvatarFallback>
                {session.user?.name?.charAt(0) || 'U'}
              </AvatarFallback>
            </Avatar>
            <div>
              <p className="font-medium">{session.user?.name}</p>
              <p className="text-sm text-gray-500">{session.user?.email}</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Button variant="outline" size="sm" asChild onClick={handleLinkClick}>
              <Link href="/account">
                <IconUser className="mr-2 h-4 w-4" />
                Profile
              </Link>
            </Button>
            <Button variant="outline" size="sm" asChild onClick={handleLinkClick}>
              <Link href="/orders">
                <IconPackage className="mr-2 h-4 w-4" />
                Orders
              </Link>
            </Button>
          </div>
        </div>
      ) : (
        <div className="p-4 border-b">
          <div className="grid grid-cols-2 gap-2">
            <Button variant="outline" asChild onClick={handleLinkClick}>
              <Link href="/auth/sign-in">Sign In</Link>
            </Button>
            <Button asChild onClick={handleLinkClick}>
              <Link href="/auth/sign-up">Sign Up</Link>
            </Button>
          </div>
        </div>
      )}

      {/* Navigation */}
      <div className="flex-1 overflow-y-auto">
        <nav className="p-4 space-y-2">
          {navigation.map((item) => (
            <div key={item.name}>
              {item.featured ? (
                <Collapsible
                  open={openItems.includes(item.name)}
                  onOpenChange={() => toggleItem(item.name)}
                >
                  <CollapsibleTrigger asChild>
                    <Button
                      variant="ghost"
                      className="w-full justify-between font-medium"
                    >
                      {item.name}
                      <IconChevronDown
                        className={`h-4 w-4 transition-transform ${
                          openItems.includes(item.name) ? 'rotate-180' : ''
                        }`}
                      />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="space-y-1 ml-4">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="w-full justify-start text-primary"
                      asChild
                      onClick={handleLinkClick}
                    >
                      <Link href={item.href}>View All {item.name}</Link>
                    </Button>
                    {item.featured.map((subItem) => (
                      <Button
                        key={subItem.name}
                        variant="ghost"
                        size="sm"
                        className="w-full justify-start"
                        asChild
                        onClick={handleLinkClick}
                      >
                        <Link href={subItem.href}>{subItem.name}</Link>
                      </Button>
                    ))}
                  </CollapsibleContent>
                </Collapsible>
              ) : (
                <Button
                  variant="ghost"
                  className="w-full justify-start font-medium"
                  asChild
                  onClick={handleLinkClick}
                >
                  <Link href={item.href}>{item.name}</Link>
                </Button>
              )}
            </div>
          ))}
        </nav>

        <Separator className="my-4" />

        {/* Additional Links */}
        <div className="p-4 space-y-2">
          <Button
            variant="ghost"
            className="w-full justify-start"
            asChild
            onClick={handleLinkClick}
          >
            <Link href="/wishlist">
              <IconHeart className="mr-2 h-4 w-4" />
              Wishlist
            </Link>
          </Button>
          <Button
            variant="ghost"
            className="w-full justify-start"
            asChild
            onClick={handleLinkClick}
          >
            <Link href="/track-order">
              <IconMapPin className="mr-2 h-4 w-4" />
              Track Order
            </Link>
          </Button>
          <Button
            variant="ghost"
            className="w-full justify-start"
            asChild
            onClick={handleLinkClick}
          >
            <Link href="/help">
              <IconHelp className="mr-2 h-4 w-4" />
              Help & Support
            </Link>
          </Button>
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t">
        <div className="space-y-2 text-sm text-gray-500">
          <div className="flex items-center space-x-2">
            <IconPhone className="h-4 w-4" />
            <span>+27 11 123 4567</span>
          </div>
          <div className="flex items-center space-x-2">
            <IconMapPin className="h-4 w-4" />
            <span>Free delivery in Johannesburg</span>
          </div>
        </div>
        
        {session && (
          <>
            <Separator className="my-3" />
            <Button
              variant="ghost"
              className="w-full justify-start text-red-600"
              onClick={() => {
                signOut();
                handleLinkClick();
              }}
            >
              <IconLogout className="mr-2 h-4 w-4" />
              Sign Out
            </Button>
          </>
        )}
      </div>
    </div>
  );
}
