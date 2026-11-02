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
    <div className="min-h-screen w-full flex items-center justify-center p-4 sm:p-6 bg-background">
      <div className="w-full max-w-[440px]">
        <Card className="w-full text-center shadow-xs border-border rounded-xl overflow-hidden">
          <CardContent className="p-6 sm:p-8">
            <div className="flex justify-center mb-6">
              <BrandMark size="default" />
            </div>

            <div className="font-mono text-xs text-muted-foreground mb-1.5">
              404
            </div>
            <h1 className="font-heading text-2xl sm:text-[30px] leading-tight font-semibold text-foreground mb-2.5">
              Page not found
            </h1>
            <p className="font-sans text-xs sm:text-sm text-muted-foreground leading-relaxed mb-6">
              The page or resource you requested does not exist or has been moved.
            </p>
            <Button asChild className="w-full h-11 rounded-pill font-medium">
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
