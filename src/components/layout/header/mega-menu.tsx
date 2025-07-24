'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuLink,
  NavigationMenuList,
  NavigationMenuTrigger,
} from '@/components/ui/navigation-menu';
import { cn } from '@/lib/utils';

interface NavigationItem {
  name: string;
  href: string;
  featured?: Array<{
    name: string;
    href: string;
  }>;
}

interface MegaMenuProps {
  item: NavigationItem;
}

export function MegaMenu({ item }: MegaMenuProps) {
  if (!item.featured) {
    return (
      <Button variant="ghost" asChild>
        <Link href={item.href} className="font-medium">
          {item.name}
        </Link>
      </Button>
    );
  }

  return (
    <NavigationMenu>
      <NavigationMenuList>
        <NavigationMenuItem>
          <NavigationMenuTrigger className="font-medium">
            {item.name}
          </NavigationMenuTrigger>
          <NavigationMenuContent>
            <div className="grid gap-3 p-6 w-[400px] lg:w-[500px] lg:grid-cols-[.75fr_1fr]">
              <div className="row-span-3">
                <NavigationMenuLink asChild>
                  <Link
                    className="flex h-full w-full select-none flex-col justify-end rounded-md bg-gradient-to-b from-muted/50 to-muted p-6 no-underline outline-none focus:shadow-md"
                    href={item.href}
                  >
                    <div className="mb-2 mt-4 text-lg font-medium">
                      {item.name} Collection
                    </div>
                    <p className="text-sm leading-tight text-muted-foreground">
                      Discover our premium {item.name.toLowerCase()} footwear collection
                    </p>
                  </Link>
                </NavigationMenuLink>
              </div>
              <div className="grid gap-2">
                {item.featured.map((subItem) => (
                  <NavigationMenuLink key={subItem.name} asChild>
                    <Link
                      href={subItem.href}
                      className={cn(
                        "block select-none space-y-1 rounded-md p-3 leading-none no-underline outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground"
                      )}
                    >
                      <div className="text-sm font-medium leading-none">
                        {subItem.name}
                      </div>
                    </Link>
                  </NavigationMenuLink>
                ))}
                <NavigationMenuLink asChild>
                  <Link
                    href={item.href}
                    className={cn(
                      "block select-none space-y-1 rounded-md p-3 leading-none no-underline outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground border-t mt-2 pt-3"
                    )}
                  >
                    <div className="text-sm font-medium leading-none text-primary">
                      View All {item.name} →
                    </div>
                  </Link>
                </NavigationMenuLink>
              </div>
            </div>
          </NavigationMenuContent>
        </NavigationMenuItem>
      </NavigationMenuList>
    </NavigationMenu>
  );
}
