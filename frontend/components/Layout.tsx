import { useOAuthParams } from '../hooks/useOAuthParams';
import { InvalidRequest } from '../components/InvalidRequest';
import { ThemeToggle } from './ThemeToggle';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';

export const Layout = ({ children }: { children: React.ReactNode }) => {
    const { isValid } = useOAuthParams();

    if (!isValid) {
        return <InvalidRequest reason="missing_params" />;
    }

    return (
        <TooltipProvider>
            <main className="min-h-dvh overflow-x-hidden w-full flex items-center justify-center relative">
                <div className="fixed inset-0 top-0 left-0 bg-mesh-warm dark:bg-mesh-cool bg-noise -z-10" />
                
                <div className="fixed top-5 right-5 z-50">
                    <ThemeToggle />
                </div>
                
                <div className="z-10 w-full relative">
                    {children}
                </div>
                
                <Logo />
            </main>
            <Toaster />
        </TooltipProvider>
    );
}

export const Logo = () => {
    return (
        <div className="fixed top-5 left-5 flex items-center gap-2 bg-background/50 backdrop-blur-md rounded-full px-4 py-2 border border-white/20 shadow-sm z-50">
            <div>
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-sparkle"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" /></svg>
            </div>
            <div>
                <p className="text-sm font-bold font-sans tracking-widest uppercase">SWYRA</p>
            </div>
        </div>
    )
}