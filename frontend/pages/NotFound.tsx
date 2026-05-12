import React from 'react';
import { Link } from 'react-router-dom';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';

export const NotFound: React.FC = () => {
  return (
    <div className="w-full max-w-3xl px-6">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-left">
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">404</p>
          <h1 className="mt-2 text-2xl font-semibold text-foreground">Page not found</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            The page you are looking for does not exist or has moved.
          </p>
          <Button asChild className="mt-6 w-full">
            <Link to="/auth" viewTransition>
              Back to authentication
            </Link>
          </Button>
        </div>
      </GlassSurface>
    </div>
  );
};
