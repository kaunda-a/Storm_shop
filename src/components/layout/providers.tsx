'use client';

import React from 'react';
import { ActiveThemeProvider } from '../active-theme';
import { AuthProvider } from '@/components/providers/session-provider';
import { ConfettiProvider } from '@/components/ui/confetti';

export default function Providers({
  activeThemeValue,
  children
}: {
  activeThemeValue: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <ActiveThemeProvider initialTheme={activeThemeValue}>
        <AuthProvider>
          <ConfettiProvider>
            {children}
          </ConfettiProvider>
        </AuthProvider>
      </ActiveThemeProvider>
    </>
  );
}
