import { auth } from "@/lib/auth"
import { NextResponse } from "next/server"

export default auth((req) => {
  const { nextUrl } = req
  const isLoggedIn = !!req.auth
  const userRole = req.auth?.user?.role

  // Define protected routes
  const isAdminRoute = nextUrl.pathname.startsWith('/dashboard')
  const isCustomerRoute = nextUrl.pathname.startsWith('/account') ||
                         nextUrl.pathname.startsWith('/orders') ||
                         nextUrl.pathname.startsWith('/checkout')
  const isAuthRoute = nextUrl.pathname.startsWith('/auth')

  // Redirect to admin sign-in if accessing admin route without auth
  if (isAdminRoute && !isLoggedIn) {
    return NextResponse.redirect(new URL('/auth/sign-in', nextUrl))
  }

  // Redirect to customer sign-in if accessing customer route without auth
  if (isCustomerRoute && !isLoggedIn) {
    return NextResponse.redirect(new URL(`/auth/customer-sign-in?callbackUrl=${encodeURIComponent(nextUrl.pathname)}`, nextUrl))
  }

  // Redirect based on role if accessing auth routes while logged in
  if (isAuthRoute && isLoggedIn) {
    if (userRole === 'ADMIN' || userRole === 'SUPER_ADMIN') {
      return NextResponse.redirect(new URL('/dashboard', nextUrl))
    } else if (userRole === 'CUSTOMER') {
      return NextResponse.redirect(new URL('/', nextUrl))
    }
  }

  // Prevent customers from accessing admin routes
  if (isAdminRoute && isLoggedIn && userRole === 'CUSTOMER') {
    return NextResponse.redirect(new URL('/', nextUrl))
  }

  return NextResponse.next()
})
export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    // Always run for API routes
    '/(api|trpc)(.*)'
  ]
};
