
import DotField from '@/components/DotBackgroudn';
import { useOAuthParams } from '../hooks/useOAuthParams';
import { InvalidRequest } from '../components/InvalidRequest';

export const Layout = ({ children }: { children: React.ReactNode }) => {
    const { isValid } = useOAuthParams();

    if (!isValid) {
        return <InvalidRequest reason="missing_params" />;
    }

    return (
        <main className="h-dvh  overflow-hidden w-dvw flex items-center justify-center relative">
            <div className="fixed inset-0 top-0 left-0 bg-slate-950/10">
                <DotField
                    dotRadius={1.5}
                    dotSpacing={18}
                    bulgeStrength={60}
                    glowRadius={100}
                    sparkle={false}
                    waveAmplitude={2}
                    cursorRadius={550}
                    cursorForce={0.51}
                    bulgeOnly
                    gradientFrom="#8300ff"
                    gradientTo="#ffffff"
                    glowColor="#1b1229"
                />
            </div>
            {children}
            <Logo />
        </main>
    );
}

export const Logo = () => {
    return (
        <div className="fixed top-5 left-5 flex items-center gap-1 bg-secondary/50 rounded-lg p-2.5 py-2">
            <div className="">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" className="lucide lucide-sparkle-icon lucide-sparkle"><path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" /></svg>
            </div>
            <div>
                <p className="text-sm font-bold font-sans">SWYRA</p>
            </div>
        </div>
    )
}