import { Metadata } from 'next';
import { SignInForm } from '@/features/auth/components/sign-in-form';

export const metadata: Metadata = {
  title: 'Sign In | Mzansi Footwear Admin',
  description: 'Sign in to your Mzansi Footwear admin account.'
};

export default function SignInPage() {
  return <SignInForm />;
}
