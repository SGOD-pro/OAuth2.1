import React, { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { toast } from 'sonner';
import { Eye, EyeOff } from 'lucide-react';
import { authClient } from '@/lib/auth-client';

interface ProvisionAdminModalProps {
  clientId: string;
  clientName?: string;
  onClose: () => void;
  onSuccess: (adminEmail: string) => void;
}

export const ProvisionAdminModal: React.FC<ProvisionAdminModalProps> = ({ clientId, clientName, onClose, onSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const { error } = await authClient.$fetch('/api/admin/users', {
        method: 'POST',
        body: { email, password, name, clientId },
      });

      if (error) {
        throw new Error((error as { message?: string }).message || error.statusText || 'Failed to provision admin');
      }

      toast.success("Administrator provisioned. User must sign in to configure two-factor authentication.");
      onSuccess(email);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to provision admin');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="sm:max-w-[500px] w-full">
        <form onSubmit={handleSubmit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>Provision Application Admin</DialogTitle>
            <DialogDescription>
              Create an administrator user account for <span className="font-mono text-foreground font-medium">{clientName || clientId}</span>.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="name" className="font-sans text-xs font-medium text-foreground">Name</Label>
              <Input
                id="name"
                placeholder="e.g. Alex Vance"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="h-9"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email" className="font-sans text-xs font-medium text-foreground">Email Address <span className="text-destructive">*</span></Label>
              <Input
                id="email"
                type="email"
                required
                placeholder="admin@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="h-9"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password" className="font-sans text-xs font-medium text-foreground">Initial Password <span className="text-destructive">*</span></Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  required
                  placeholder="Minimum 12 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pr-10 h-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
            </div>
          </div>

          <DialogFooter className="mt-4">
            <Button type="button" variant="outline" onClick={onClose} disabled={loading} className="h-9">
              Cancel
            </Button>
            <Button type="submit" disabled={loading} className="h-9">
              {loading ? "Provisioning..." : "Provision admin"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};
