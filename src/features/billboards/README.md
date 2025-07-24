# Billboard Feature

The Billboard feature provides a public-facing interface for customers to view promotional content, announcements, and campaigns created by administrators.

## Overview

Billboards are promotional content pieces that can be displayed across different positions in the shop. They support various types of content including images, videos, and action links.

## Features

### Billboard Types
- **PROMOTIONAL** - General promotional content
- **ANNOUNCEMENT** - Important announcements
- **PRODUCT_LAUNCH** - New product launches
- **SALE** - Sales and discounts
- **SEASONAL** - Seasonal campaigns
- **SYSTEM_MESSAGE** - System-wide messages
- **BRAND_CAMPAIGN** - Brand-specific campaigns

### Billboard Positions
- **HEADER** - Top of pages
- **SIDEBAR** - Side navigation areas
- **FOOTER** - Bottom of pages
- **MODAL** - Popup overlays
- **DASHBOARD_TOP** - Top of dashboard
- **DASHBOARD_BOTTOM** - Bottom of dashboard
- **PRODUCT_PAGE** - Product detail pages
- **CHECKOUT** - Checkout process

## Pages

### `/billboards` - Billboard Listing
- Displays all active billboards
- Filterable by type and position
- Searchable by title and description
- Responsive card layout with preview images
- Shows expiration dates and status

### `/billboards/[billboardId]` - Billboard Details
- Full billboard preview using the Billboard component
- Detailed information including:
  - Basic information (title, description, type, position)
  - Media content (images, videos)
  - Action links and button text
  - Schedule and status information
  - Creator information and timestamps

## Components

### `BillboardListingPage`
- Server-side rendered listing component
- Handles pagination and filtering
- Responsive design with loading states
- Empty state handling

### `BillboardViewPage`
- Individual billboard detail view
- Uses the shared Billboard UI component for preview
- Comprehensive information display
- Error handling and not found states

## Navigation

Billboards are accessible through:
- **Header Navigation** - "Promotions" link
- **Footer Navigation** - "Promotions" link in shop section
- **Direct URLs** - `/billboards` and `/billboards/[id]`

## SEO Features

- **Dynamic metadata** generation for individual billboards
- **Open Graph** support with billboard images
- **Structured data** for better search engine understanding
- **Breadcrumb navigation** for better UX and SEO

## Data Flow

1. **Admin creates billboards** in the admin interface
2. **BillboardService** manages data access and filtering
3. **Shop pages** display active billboards to customers
4. **Billboard components** handle presentation and interaction

## Integration

The billboard feature integrates with:
- **Admin dashboard** for content management
- **Navigation system** for easy access
- **SEO system** for search optimization
- **Responsive design** for all device types

## Usage Examples

### Display billboards in components
```tsx
import { BillboardContainer } from '@/components/layout/billboard-container'

// Show header billboards
<BillboardContainer position="HEADER" />

// Show compact sidebar billboards
<BillboardContainer position="SIDEBAR" compact />
```

### Link to billboard pages
```tsx
import Link from 'next/link'

// Link to all billboards
<Link href="/billboards">View Promotions</Link>

// Link to specific billboard
<Link href={`/billboards/${billboard.id}`}>View Details</Link>
```

## Future Enhancements

- **Analytics tracking** for billboard performance
- **A/B testing** for different billboard versions
- **Personalization** based on customer preferences
- **Interactive elements** like forms or quizzes
- **Video autoplay** controls and settings
