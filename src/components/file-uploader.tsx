'use client';

import * as React from 'react';
import Image from 'next/image';
import Dropzone, { FileRejection } from 'react-dropzone';
import { IconX, IconUpload } from '@tabler/icons-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useControllableState } from '@/hooks/use-controllable-state';
import { cn, formatBytes } from '@/lib/utils';

interface FileUploaderProps {
  disabled?: boolean;
  value?: string;
  onChange?: (url: string | undefined) => void;
}

export const FileUploader: React.FC<FileUploaderProps> = ({
  disabled,
  value,
  onChange,
}) => {
  const [imageUrl, setImageUrl] = useControllableState<string | undefined>({
    prop: value,
    onChange,
    
  });
  const [uploading, setUploading] = React.useState(false);
  const [progress, setProgress] = React.useState(0);

  const handleUpload = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    setUploading(true);
    setProgress(0);

    try {
      const res = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        throw new Error('Upload failed');
      }

      const data = await res.json();
      setImageUrl(data.url);
      toast.success('Upload successful!');
    } catch (error) {
      toast.error((error as Error).message || 'Upload error');
    } finally {
      setUploading(false);
      setProgress(100);
    }
  };

  const onDrop = (acceptedFiles: File[], _fileRejections: FileRejection[]) => {
    if (acceptedFiles.length > 0) {
      handleUpload(acceptedFiles[0]);
    }
  };

  return (
    <div className="space-y-4">
      {!imageUrl && (
        <Dropzone onDrop={onDrop} disabled={disabled || uploading} multiple={false}>
          {({ getRootProps, getInputProps }) => (
            <div
              {...getRootProps()}
              className={cn(
                'border border-dashed border-gray-300 p-4 sm:p-6 rounded-lg text-center cursor-pointer hover:bg-gray-100 transition-colors',
                disabled && 'opacity-50 cursor-not-allowed'
              )}
            >
              <input {...getInputProps()} />
              <div className="flex flex-col items-center gap-2">
                <IconUpload className="h-5 w-5 sm:h-6 sm:w-6 text-muted-foreground" />
                <p className="text-xs sm:text-sm text-muted-foreground">
                  Drag & drop or click to upload image
                </p>
              </div>
            </div>
          )}
        </Dropzone>
      )}

      {uploading && <Progress value={progress} />}

      {imageUrl && (
        <div className="relative w-full max-w-[200px] sm:max-w-[250px] mx-auto">
          <ScrollArea className="rounded-md overflow-hidden w-full aspect-square border">
            <Image
              src={imageUrl}
              alt="Uploaded image"
              width={250}
              height={250}
              className="object-cover w-full h-full"
            />
          </ScrollArea>

          <Button
            type="button"
            size="icon"
            variant="destructive"
            className="absolute top-2 right-2 rounded-full h-6 w-6 sm:h-8 sm:w-8"
            onClick={() => setImageUrl('')}
          >
            <IconX className="h-3 w-3 sm:h-4 sm:w-4" />
          </Button>
        </div>
      )}
    </div>
  );
};

