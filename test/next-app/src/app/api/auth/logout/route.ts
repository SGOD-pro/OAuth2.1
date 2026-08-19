import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const postLogoutUrl = new URL('/', request.url).toString();
  const response = NextResponse.redirect(postLogoutUrl, 303);
  response.cookies.delete('auth_session');
  response.cookies.delete('oauth_verifier');
  response.cookies.delete('oauth_state');
  return response;
}

export async function GET(request: NextRequest) {
  const postLogoutUrl = new URL('/', request.url).toString();
  const response = NextResponse.redirect(postLogoutUrl, 303);
  response.cookies.delete('auth_session');
  response.cookies.delete('oauth_verifier');
  response.cookies.delete('oauth_state');
  return response;
}
