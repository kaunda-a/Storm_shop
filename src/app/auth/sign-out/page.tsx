'use client';

import { useEffect, useState } from 'react';
import { signOut, useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Confetti } from '@/components/ui/confetti';
import { IconLogout, IconArrowLeft } from '@tabler/icons-react';

export default function SignOutPage() {
  const [showConfetti, setShowConfetti] = useState(false);
  const [isSigningOut, setIsSigningOut] = useState(false);
  const { data: session } = useSession();
  const router = useRouter();

  useEffect(() => {
    // Show confetti when the page loads
    setShowConfetti(true);
    
    // Auto-hide confetti after 3 seconds
    const timer = setTimeout(() => {
      setShowConfetti(false);
    }, 3000);

    return () => clearTimeout(timer);
  }, []);

  const handleSignOut = async () => {
    setIsSigningOut(true);
    
    // Show confetti again for the sign-out action
    setShowConfetti(true);
    
    // Wait a moment for confetti to show
    setTimeout(async () => {
      await signOut({ 
        callbackUrl: '/auth/sign-in',
        redirect: true 
      });
    }, 1000);
  };

  const handleGoBack = () => {
    router.back();
  };

  const userEmail = session?.user?.email || 'User';
  const userName = userEmail.split('@')[0];

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted p-4">
      <Confetti 
        active={showConfetti} 
        config={{
          elementCount: 60,
          colors: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'],
          duration: 3000,
          spread: 60,
          startVelocity: 50
        }} 
      />
      
      <Card className="w-full max-w-md">
        <CardHeader className="text-center space-y-4">
          <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center">
            <IconLogout className="w-8 h-8 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl">Sign Out</CardTitle>
            <CardDescription className="text-base mt-2">
              Thanks for using Mzansi Footwear Admin, {userName}!
            </CardDescription>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-6">
          <div className="text-center text-sm text-muted-foreground">
            <p>You're about to sign out of your admin account.</p>
            <p className="mt-1">We hope you had a productive session! 🎉</p>
          </div>
          
          <div className="space-y-3">
            <Button 
              onClick={handleSignOut}
              disabled={isSigningOut}
              className="w-full"
              size="lg"
            >
              {isSigningOut ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                  Signing out...
                </>
              ) : (
                <>
                  <IconLogout className="mr-2 h-4 w-4" />
                  Confirm Sign Out
                </>
              )}
            </Button>
            
            <Button 
              onClick={handleGoBack}
              variant="outline"
              disabled={isSigningOut}
              className="w-full"
              size="lg"
            >
              <IconArrowLeft className="mr-2 h-4 w-4" />
              Go Back to Dashboard
            </Button>
          </div>
          
          <div className="text-center text-xs text-muted-foreground">
            <p>You'll be redirected to the sign-in page after signing out.</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
