import { ImageResponse } from 'next/og';
// Logo will be handled differently in OpenGraph image
import { join } from 'path';
import { readFile } from 'fs/promises';

export type Props = {
  title?: string;
};

export default async function OpengraphImage(
  props?: Props
): Promise<ImageResponse> {
  const { title } = {
    ...{
      title: 'Mzansi Footwear'
    },
    ...props
  };

  let font: ArrayBuffer | undefined;

  try {
    const file = await readFile(join(process.cwd(), './src/fonts/Inter-Bold.ttf'));
    font = Uint8Array.from(file).buffer;
  } catch (error) {
    console.warn('Could not load font file for opengraph image:', error);
    // Continue without custom font
  }

  return new ImageResponse(
    (
      <div tw="flex h-full w-full flex-col items-center justify-center bg-black">
        <div tw="flex flex-none items-center justify-center border border-neutral-700 h-[160px] w-[160px] rounded-3xl">
          <div tw="text-white text-4xl font-bold">MF</div>
        </div>
        <p tw="mt-12 text-6xl font-bold text-white">{title}</p>
      </div>
    ),
    {
      width: 1200,
      height: 630,
      ...(font && {
        fonts: [
          {
            name: 'Inter',
            data: font,
            style: 'normal',
            weight: 700
          }
        ]
      })
    }
  );
}
