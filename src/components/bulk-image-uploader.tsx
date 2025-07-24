'use client';

import * as React from 'react';
import Image from 'next/image';
import Dropzone, { FileRejection } from 'react-dropzone';
import { IconX, IconUpload, IconArrowUp, IconArrowDown, IconStar, IconStarFilled } from '@tabler/icons-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useControllableState } from '@/hooks/use-controllable-state';
import { cn, formatBytes } from '@/lib/utils';

export interface ProductImage {
  id?: string;
  url: string;
  altText?: string;
  sortOrder: number;
  isPrimary: boolean;
}

interface BulkImageUploaderProps {
  disabled?: boolean;
  value?: ProductImage[];
  onChange?: (images: ProductImage[] | undefined) => void;
  maxImages?: number;
}

export const BulkImageUploader: React.FC<BulkImageUploaderProps> = ({
  disabled,
  value = [],
  onChange,
  maxImages = 10,
}) => {
  const [images, setImages] = useControllableState<ProductImage[]>({
    prop: value,
    onChange,
    defaultProp: [],
  });

  // Ensure images is never undefined
  const safeImages = images || [];
  const [uploading, setUploading] = React.useState(false);
  const [uploadProgress, setUploadProgress] = React.useState<{ [key: string]: number }>({});

  const handleUpload = async (files: File[]) => {
    if (safeImages.length + files.length > maxImages) {
      toast.error(`Maximum ${maxImages} images allowed`);
      return;
    }

    setUploading(true);
    setUploadProgress({ bulk: 0 });

    try {
      const formData = new FormData();
      files.forEach((file) => {
        formData.append('files', file);
      });

      setUploadProgress({ bulk: 25 });

      const res = await fetch('/api/upload/bulk', {
        method: 'POST',
        body: formData,
      });

      setUploadProgress({ bulk: 75 });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Bulk upload failed');
      }

      const data = await res.json();

      const newImages: ProductImage[] = data.images.map((img: any, index: number) => ({
        url: img.url,
        altText: img.originalName.split('.')[0],
        sortOrder: safeImages.length + index,
        isPrimary: safeImages.length === 0 && index === 0, // First image is primary if no images exist
      }));

      setUploadProgress({ bulk: 100 });
      setImages([...safeImages, ...newImages]);
      toast.success(`${files.length} image(s) uploaded successfully!`);
    } catch (error) {
      toast.error((error as Error).message || 'Upload error');
    } finally {
      setUploading(false);
      setUploadProgress({});
    }
  };

  const onDrop = (acceptedFiles: File[], fileRejections: FileRejection[]) => {
    if (fileRejections.length > 0) {
      fileRejections.forEach((rejection) => {
        toast.error(`${rejection.file.name}: ${rejection.errors[0].message}`);
      });
    }
    
    if (acceptedFiles.length > 0) {
      handleUpload(acceptedFiles);
    }
  };

  const removeImage = (index: number) => {
    const newImages = safeImages.filter((_, i) => i !== index);
    // Reorder remaining images
    const reorderedImages = newImages.map((img, i) => ({
      ...img,
      sortOrder: i,
      isPrimary: i === 0 && newImages.length > 0 ? true : (i === 0 ? false : img.isPrimary && i !== 0 ? false : img.isPrimary)
    }));
    setImages(reorderedImages);
  };

  const setPrimaryImage = (index: number) => {
    const newImages = safeImages.map((img, i) => ({
      ...img,
      isPrimary: i === index
    }));
    setImages(newImages);
  };

  const updateAltText = (index: number, altText: string) => {
    const newImages = safeImages.map((img, i) =>
      i === index ? { ...img, altText } : img
    );
    setImages(newImages);
  };

  const moveImage = (index: number, direction: 'up' | 'down') => {
    const newIndex = direction === 'up' ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= safeImages.length) return;

    const newImages = [...safeImages];
    [newImages[index], newImages[newIndex]] = [newImages[newIndex], newImages[index]];

    // Update sort orders
    const reorderedImages = newImages.map((img, i) => ({
      ...img,
      sortOrder: i
    }));

    setImages(reorderedImages);
  };

  return (
    <div className="space-y-4">
      {/* Upload Area */}
      <Dropzone 
        onDrop={onDrop} 
        disabled={disabled || uploading || safeImages.length >= maxImages}
        multiple={true}
        accept={{
          'image/*': ['.jpeg', '.jpg', '.png', '.webp', '.gif']
        }}
        maxSize={5 * 1024 * 1024} // 5MB
      >
        {({ getRootProps, getInputProps, isDragActive }) => (
          <div
            {...getRootProps()}
            className={cn(
              'border-2 border-dashed border-gray-300 p-6 rounded-lg text-center cursor-pointer transition-colors',
              isDragActive && 'border-blue-500 bg-blue-50',
              (disabled || uploading || safeImages.length >= maxImages) && 'opacity-50 cursor-not-allowed',
              !isDragActive && 'hover:bg-gray-50'
            )}
          >
            <input {...getInputProps()} />
            <div className="flex flex-col items-center gap-2">
              <IconUpload className="h-8 w-8 text-muted-foreground" />
              <div>
                <p className="text-sm font-medium">
                  {isDragActive ? 'Drop images here' : 'Drag & drop images or click to upload'}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  {safeImages.length}/{maxImages} images • Max 5MB per image • JPEG, PNG, WebP, GIF
                </p>
              </div>
            </div>
          </div>
        )}
      </Dropzone>

      {/* Upload Progress */}
      {uploading && Object.keys(uploadProgress).length > 0 && (
        <div className="space-y-2">
          {Object.entries(uploadProgress).map(([fileId, progress]) => (
            <div key={fileId} className="space-y-1">
              <div className="flex justify-between text-xs">
                <span>Uploading...</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          ))}
        </div>
      )}

      {/* Image Grid */}
      {safeImages.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <Label className="text-sm font-medium">Product Images ({safeImages.length})</Label>
            <p className="text-xs text-muted-foreground">Use arrows to reorder • Star to set primary</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {safeImages.map((image, index) => (
              <div
                key={`${image.url}-${index}`}
                className={cn(
                  "relative group border rounded-lg overflow-hidden bg-white",
                  image.isPrimary && "ring-2 ring-blue-500"
                )}
              >
                {/* Reorder Buttons */}
                <div className="absolute top-2 left-2 z-10 flex flex-col gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="h-6 w-6 bg-black/50 hover:bg-black/70"
                    onClick={() => moveImage(index, 'up')}
                    disabled={index === 0}
                  >
                    <IconArrowUp className="h-3 w-3 text-white" />
                  </Button>
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="h-6 w-6 bg-black/50 hover:bg-black/70"
                    onClick={() => moveImage(index, 'down')}
                    disabled={index === safeImages.length - 1}
                  >
                    <IconArrowDown className="h-3 w-3 text-white" />
                  </Button>
                </div>

                {/* Primary Star */}
                <Button
                  type="button"
                  size="icon"
                  variant="ghost"
                  className="absolute top-2 right-12 z-10 h-8 w-8 bg-black/50 hover:bg-black/70 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={() => setPrimaryImage(index)}
                >
                  {image.isPrimary ? (
                    <IconStarFilled className="h-4 w-4 text-yellow-400" />
                  ) : (
                    <IconStar className="h-4 w-4 text-white" />
                  )}
                </Button>

                {/* Remove Button */}
                <Button
                  type="button"
                  size="icon"
                  variant="destructive"
                  className="absolute top-2 right-2 z-10 h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={() => removeImage(index)}
                >
                  <IconX className="h-4 w-4" />
                </Button>

                {/* Image */}
                <div className="aspect-square relative">
                  <Image
                    src={image.url}
                    alt={image.altText || `Product image ${index + 1}`}
                    fill
                    className="object-cover"
                  />
                </div>

                {/* Alt Text Input */}
                <div className="p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs">Alt Text:</Label>
                    {image.isPrimary && (
                      <span className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Primary</span>
                    )}
                  </div>
                  <Input
                    value={image.altText || ''}
                    onChange={(e) => updateAltText(index, e.target.value)}
                    placeholder="Describe this image..."
                    className="text-xs h-8"
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
