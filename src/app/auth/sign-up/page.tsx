import { Metadata } from 'next';
import { redirect } from 'next/navigation';

export const metadata: Metadata = {
  title: 'Sign Up | Mzansi Footwear Admin',
  description: 'Create your Mzansi Footwear admin account.'
};

export default function SignUpPage() {
  // For now, redirect to sign-in since we're using admin-only accounts
  // In the future, this could be a proper sign-up form
  redirect('/auth/sign-in');
}
