'use client';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { zodResolver } from '@hookform/resolvers/zod';
import { IconLoader2, IconPlus, IconEdit } from '@tabler/icons-react';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { toast } from 'sonner';
import * as z from 'zod';

const brandFormSchema = z.object({
  name: z.string().min(1, 'Brand name is required').max(100, 'Name must be less than 100 characters'),
  description: z.string().optional(),
  logoUrl: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  websiteUrl: z.string().url('Must be a valid URL').optional().or(z.literal('')),
  isActive: z.boolean().default(true),
});

type BrandFormValues = z.infer<typeof brandFormSchema>;

interface BrandFormDialogProps {
  brand?: any;
  onSuccess?: () => void;
  trigger?: React.ReactNode;
}

export function BrandFormDialog({ brand, onSuccess, trigger }: BrandFormDialogProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const isEdit = !!brand;

  const form = useForm<BrandFormValues>({
    resolver: zodResolver(brandFormSchema),
    defaultValues: {
      name: brand?.name || '',
      description: brand?.description || '',
      logoUrl: brand?.logoUrl || '',
      websiteUrl: brand?.websiteUrl || '',
      isActive: brand?.isActive ?? true,
    },
  });

  const onSubmit = async (data: BrandFormValues) => {
    try {
      setLoading(true);

      const formattedData = {
        ...data,
        description: data.description || undefined,
        logoUrl: data.logoUrl || undefined,
        websiteUrl: data.websiteUrl || undefined,
      };

      const url = isEdit ? `/api/brands/${brand.id}` : '/api/brands';
      const method = isEdit ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formattedData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Something went wrong');
      }

      toast.success(isEdit ? 'Brand updated successfully' : 'Brand created successfully');
      setOpen(false);
      form.reset();
      onSuccess?.();
    } catch (error: any) {
      // Error already handled by toast.error below
      toast.error(error.message || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button size="sm">
            {isEdit ? (
              <>
                <IconEdit className="mr-2 h-4 w-4" />
                Edit
              </>
            ) : (
              <>
                <IconPlus className="mr-2 h-4 w-4" />
                Add Brand
              </>
            )}
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="w-[95vw] max-w-[425px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit Brand' : 'Create Brand'}</DialogTitle>
          <DialogDescription>
            {isEdit ? 'Update the brand information.' : 'Add a new brand for organizing products.'}
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 px-1">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">Brand Name</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Enter brand name"
                      className="text-sm"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">Description (Optional)</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="Enter brand description"
                      className="min-h-[60px] sm:min-h-[80px] text-sm resize-none"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="logoUrl"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">Logo URL (Optional)</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="https://example.com/logo.jpg"
                      className="text-sm"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="websiteUrl"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-sm font-medium">Website URL (Optional)</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="https://brand-website.com"
                      className="text-sm"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="isActive"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 sm:p-4">
                  <div className="space-y-0.5 flex-1 min-w-0">
                    <FormLabel className="text-sm sm:text-base font-medium">Active Status</FormLabel>
                    <div className="text-xs sm:text-sm text-muted-foreground">
                      Enable this brand to be available for products
                    </div>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <DialogFooter className="flex flex-col sm:flex-row gap-2 sm:gap-0">
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
                disabled={loading}
                className="w-full sm:w-auto text-sm"
              >
                Cancel
              </Button>
              <Button type="submit" disabled={loading} className="w-full sm:w-auto text-sm">
                {loading && <IconLoader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isEdit ? 'Update Brand' : 'Create Brand'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
