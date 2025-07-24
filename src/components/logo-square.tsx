import clsx from 'clsx';
import Image from 'next/image';

export default function LogoSquare({ size }: { size?: 'sm' | undefined }) {
  return (
    <div
      className={clsx(
        'flex flex-none items-center justify-center border border-neutral-200 bg-white dark:border-neutral-700 dark:bg-black',
        {
          'h-[40px] w-[40px] rounded-xl': !size,
          'h-[30px] w-[30px] rounded-lg': size === 'sm'
        }
      )}
    >
      <Image
        src="/logo.svg"
        alt="Mzansi Footwear"
        width={size === 'sm' ? 10 : 16}
        height={size === 'sm' ? 10 : 16}
        className="object-contain"
      />
    </div>
  );
}
