import { Metadata } from 'next';
import { CustomerSignInForm } from '@/features/auth/components/customer-sign-in-form';

export const metadata: Metadata = {
  title: 'Sign In | Mzansi Footwear',
  description: 'Sign in to your Mzansi Footwear account to shop and manage your orders.'
};

export default function CustomerSignInPage() {
  return <CustomerSignInForm />;
}
