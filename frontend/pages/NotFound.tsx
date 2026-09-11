import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { BrandMark } from '@/components/BrandMark';
import { usePageTitle } from '@/hooks/usePageTitle';
import { ArrowLeft } from 'lucide-react';

export const NotFound: React.FC = () => {
  usePageTitle('Page not found');

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6 bg-background">
      <div className="w-full max-w-[460px]">
        <Card className="w-full text-center shadow-lg border-border">
          <CardContent className="p-8 sm:p-[34px]">
            <div className="flex justify-center mb-6">
              <BrandMark size="md" />
            </div>

            <div className="font-mono text-xs uppercase tracking-widest text-muted-foreground mb-2">
              404 // Error
            </div>
            <h1 className="font-heading text-[34px] leading-tight font-semibold text-foreground mb-3">
              Page not found
            </h1>
            <p className="font-sans text-sm text-muted-foreground leading-relaxed mb-8">
              The page or resource you requested does not exist or has been moved.
            </p>
            <Button asChild className="w-full h-10">
              <Link to="/auth" className="flex items-center justify-center gap-2">
                <ArrowLeft className="size-4" /> Return to sign in
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};
