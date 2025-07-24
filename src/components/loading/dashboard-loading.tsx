'use client';

import { LoadingSkeleton, LoadingCard, LoadingTable } from '@/components/ui/loading';
import { Card, CardContent, CardHeader } from '@/components/ui/card';

// Dashboard Overview Loading
export function DashboardOverviewLoading() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <LoadingSkeleton className="h-8 w-64" />
        <LoadingSkeleton className="h-4 w-96" />
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <LoadingSkeleton className="h-4 w-24" />
              <LoadingSkeleton className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <LoadingSkeleton className="h-8 w-16 mb-2" />
              <LoadingSkeleton className="h-3 w-32" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader>
            <LoadingSkeleton className="h-6 w-32" />
          </CardHeader>
          <CardContent>
            <LoadingSkeleton className="h-64 w-full" />
          </CardContent>
        </Card>
        <Card className="col-span-3">
          <CardHeader>
            <LoadingSkeleton className="h-6 w-24" />
          </CardHeader>
          <CardContent>
            <LoadingSkeleton className="h-64 w-full" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Product List Loading
export function ProductListLoading() {
  return (
    <div className="space-y-4">
      {/* Header with actions */}
      <div className="flex items-center justify-between">
        <LoadingSkeleton className="h-8 w-48" />
        <LoadingSkeleton className="h-10 w-32" />
      </div>

      {/* Filters */}
      <div className="flex items-center space-x-2">
        <LoadingSkeleton className="h-10 w-64" />
        <LoadingSkeleton className="h-10 w-32" />
        <LoadingSkeleton className="h-10 w-32" />
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-6">
          <LoadingTable rows={8} columns={6} />
        </CardContent>
      </Card>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <LoadingSkeleton className="h-4 w-32" />
        <div className="flex items-center space-x-2">
          <LoadingSkeleton className="h-8 w-8" />
          <LoadingSkeleton className="h-8 w-8" />
          <LoadingSkeleton className="h-8 w-8" />
          <LoadingSkeleton className="h-8 w-8" />
        </div>
      </div>
    </div>
  );
}

// Form Loading
export function FormLoading() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <LoadingSkeleton className="h-8 w-8" />
        <LoadingSkeleton className="h-8 w-48" />
      </div>

      {/* Form Card */}
      <Card>
        <CardHeader>
          <LoadingSkeleton className="h-6 w-32" />
          <LoadingSkeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Form Fields */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <LoadingSkeleton className="h-4 w-24" />
                <LoadingSkeleton className="h-10 w-full" />
              </div>
            ))}
          </div>

          {/* Large text area */}
          <div className="space-y-2">
            <LoadingSkeleton className="h-4 w-24" />
            <LoadingSkeleton className="h-32 w-full" />
          </div>

          {/* Image upload area */}
          <div className="space-y-2">
            <LoadingSkeleton className="h-4 w-24" />
            <LoadingSkeleton className="h-48 w-full" />
          </div>

          {/* Action buttons */}
          <div className="flex justify-end space-x-2">
            <LoadingSkeleton className="h-10 w-20" />
            <LoadingSkeleton className="h-10 w-24" />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Order Details Loading
export function OrderDetailsLoading() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <LoadingSkeleton className="h-8 w-48" />
          <LoadingSkeleton className="h-4 w-32" />
        </div>
        <div className="flex space-x-2">
          <LoadingSkeleton className="h-10 w-24" />
          <LoadingSkeleton className="h-10 w-24" />
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Order Info */}
        <div className="md:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <LoadingSkeleton className="h-6 w-32" />
            </CardHeader>
            <CardContent>
              <LoadingTable rows={3} columns={4} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <LoadingSkeleton className="h-6 w-40" />
            </CardHeader>
            <CardContent className="space-y-4">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-center space-x-4 p-4 border rounded">
                  <LoadingSkeleton className="h-16 w-16" />
                  <div className="flex-1 space-y-2">
                    <LoadingSkeleton className="h-4 w-48" />
                    <LoadingSkeleton className="h-3 w-32" />
                  </div>
                  <LoadingSkeleton className="h-4 w-16" />
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <LoadingSkeleton className="h-6 w-32" />
            </CardHeader>
            <CardContent className="space-y-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex justify-between">
                  <LoadingSkeleton className="h-4 w-24" />
                  <LoadingSkeleton className="h-4 w-16" />
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <LoadingSkeleton className="h-6 w-40" />
            </CardHeader>
            <CardContent className="space-y-4">
              <LoadingSkeleton className="h-16 w-full" />
              <LoadingSkeleton className="h-10 w-full" />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
