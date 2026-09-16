import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { Eye, EyeOff, Plus, Pencil, Trash2, Shield, UserPlus, RefreshCw, Globe, CheckCircle2, XCircle } from 'lucide-react';
import { apiFetch } from '@/lib/api';
import { csrfHeaders } from '@/lib/csrf';

export interface AppAdmin {
  id: string;
  email: string;
  name?: string;
  redirectUrl: string;
  isActive: boolean;
  totpEnabled?: boolean;
  loginCount: number;
  lastLoginAt?: string | null;
  createdAt: string;
}

interface AppAdminManagerProps {
  clientId: string;
  clientName?: string;
  allowedOrigins?: string[];
  redirectUris?: string[];
}

export const AppAdminManager: React.FC<AppAdminManagerProps> = ({
  clientId,
  clientName,
  allowedOrigins = [],
  redirectUris = [],
}) => {
  const candidateOrigins = React.useMemo(() => {
    const set = new Set<string>();
    (allowedOrigins || []).forEach((o) => {
      try {
        set.add(new URL(o).origin);
      } catch {
        set.add(o.replace(/\/$/, ''));
      }
    });
    (redirectUris || []).forEach((u) => {
      try {
        set.add(new URL(u).origin);
      } catch {}
    });
    return Array.from(set).filter(Boolean);
  }, [allowedOrigins, redirectUris]);
  const [admins, setAdmins] = useState<AppAdmin[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Add state
  const [isAdding, setIsAdding] = useState(false);
  const [addForm, setAddForm] = useState({ email: '', password: '', name: '', redirectUrl: '' });
  const [addLoading, setAddLoading] = useState(false);
  const [showAddPassword, setShowAddPassword] = useState(false);

  // Edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ email: '', password: '', name: '', redirectUrl: '', isActive: true });
  const [editLoading, setEditLoading] = useState(false);
  const [showEditPassword, setShowEditPassword] = useState(false);

  // Delete state
  const [deletingAdmin, setDeletingAdmin] = useState<AppAdmin | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchAdmins = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiFetch(`/api/admin/clients/${clientId}/app-admins`);
      if (!res.ok) throw new Error(`Failed to load admins (${res.status})`);
      const data = await res.json();
      setAdmins(data.admins || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load application administrators');
    } finally {
      setLoading(false);
    }
  }, [clientId]);

  useEffect(() => {
    void fetchAdmins();
  }, [fetchAdmins]);

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddLoading(true);
    try {
      const res = await apiFetch(`/api/admin/clients/${clientId}/app-admins`, {
        method: 'POST',
        headers: {
          ...csrfHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(addForm),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Failed to create application administrator');
      }

      toast.success(`Administrator "${data.admin.email}" added for ${clientName || 'application'}`);
      setAdmins((prev) => [data.admin, ...prev]);
      setIsAdding(false);
      setAddForm({ email: '', password: '', name: '', redirectUrl: '' });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to add administrator');
    } finally {
      setAddLoading(false);
    }
  };

  const handleStartEdit = (admin: AppAdmin) => {
    setEditingId(admin.id);
    setEditForm({
      email: admin.email,
      password: '',
      name: admin.name || '',
      redirectUrl: admin.redirectUrl || '',
      isActive: admin.isActive,
    });
    setShowEditPassword(false);
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingId) return;
    setEditLoading(true);

    try {
      const payload: Record<string, any> = {
        email: editForm.email,
        name: editForm.name,
        redirectUrl: editForm.redirectUrl,
        isActive: editForm.isActive,
      };
      if (editForm.password.trim()) {
        payload.password = editForm.password;
      }

      const res = await apiFetch(`/api/admin/clients/${clientId}/app-admins/${editingId}`, {
        method: 'PUT',
        headers: {
          ...csrfHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Failed to update administrator');
      }

      toast.success('Administrator updated successfully');
      setAdmins((prev) => prev.map((a) => (a.id === editingId ? data.admin : a)));
      setEditingId(null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update administrator');
    } finally {
      setEditLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!deletingAdmin) return;
    setDeleteLoading(true);

    try {
      const res = await apiFetch(`/api/admin/clients/${clientId}/app-admins/${deletingAdmin.id}`, {
        method: 'DELETE',
        headers: {
          ...csrfHeaders(),
        },
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Failed to remove administrator');
      }

      toast.success(`Administrator "${deletingAdmin.email}" removed`);
      setAdmins((prev) => prev.filter((a) => a.id !== deletingAdmin.id));
      setDeletingAdmin(null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to remove administrator');
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <div className="space-y-3 pt-2">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-primary/10 text-primary">
            <Shield className="size-4" />
          </div>
          <div>
            <h4 className="font-heading text-sm font-semibold text-foreground tracking-tight">
              Application Administrators
            </h4>
            <p className="font-sans text-xs text-muted-foreground">
              Dedicated admin accounts for {clientName || 'this application'}&apos;s internal admin panel.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground"
            onClick={() => void fetchAdmins()}
            title="Refresh administrators list"
          >
            <RefreshCw className="size-3.5" />
          </Button>

          {!isAdding && !editingId && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-7 text-xs rounded-md gap-1 font-sans"
              onClick={() => {
                setIsAdding(true);
                if (candidateOrigins.length > 0 && !addForm.redirectUrl) {
                  setAddForm((prev) => ({ ...prev, redirectUrl: `${candidateOrigins[0]}/admin` }));
                }
              }}
            >
              <Plus className="size-3.5" />
              Add Admin
            </Button>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="p-6 text-center flex flex-col items-center justify-center bg-background border border-border rounded-md text-muted-foreground">
          <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent mb-2" />
          <span className="font-sans text-xs">Loading administrators...</span>
        </div>
      ) : error ? (
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md flex items-center justify-between">
          <span className="font-sans text-xs text-destructive">{error}</span>
          <Button variant="outline" size="sm" onClick={() => void fetchAdmins()} className="h-7 text-xs">
            Retry
          </Button>
        </div>
      ) : (
        <div className="bg-background border border-border rounded-md overflow-hidden">
          {/* Add Admin Inline Form */}
          {isAdding && (
            <div className="p-4 bg-secondary/30 border-b border-border">
              <div className="flex items-center justify-between mb-3">
                <span className="font-heading text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <UserPlus className="size-3.5 text-primary" />
                  New Application Administrator
                </span>
                <span className="text-[11px] text-muted-foreground">Password min 12 chars with symbol & number</span>
              </div>

              <form onSubmit={handleAddSubmit} className="space-y-3">
                <div className="grid sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label className="text-[11px] text-foreground font-medium">Name / Title</Label>
                    <Input
                      placeholder="e.g. Lead Administrator"
                      value={addForm.name}
                      onChange={(e) => setAddForm({ ...addForm, name: e.target.value })}
                      className="h-8 text-xs bg-card"
                    />
                  </div>

                  <div className="space-y-1">
                    <Label className="text-[11px] text-foreground font-medium">
                      Email Address <span className="text-destructive">*</span>
                    </Label>
                    <Input
                      type="email"
                      required
                      placeholder="admin@app.com"
                      value={addForm.email}
                      onChange={(e) => setAddForm({ ...addForm, email: e.target.value })}
                      className="h-8 text-xs bg-card"
                    />
                  </div>

                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <Label className="text-[11px] text-foreground font-medium">
                        Redirect URL <span className="text-destructive">*</span>
                      </Label>
                      {candidateOrigins.length > 0 && (
                        <span className="text-[10px] text-muted-foreground font-sans">Must match app origin</span>
                      )}
                    </div>
                    <Input
                      required
                      placeholder="https://app.domain.com/admin/dashboard"
                      value={addForm.redirectUrl}
                      onChange={(e) => setAddForm({ ...addForm, redirectUrl: e.target.value })}
                      className="h-8 text-xs font-mono bg-card"
                    />
                    {candidateOrigins.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 pt-0.5">
                        <span className="text-[10px] text-muted-foreground font-sans">Quick fill:</span>
                        {candidateOrigins.map((orig) => (
                          <button
                            key={orig}
                            type="button"
                            className="text-[10px] font-mono bg-secondary hover:bg-secondary/80 border border-border px-1.5 py-0.5 rounded text-foreground transition-colors cursor-pointer"
                            onClick={() => setAddForm((prev) => ({ ...prev, redirectUrl: `${orig}/admin` }))}
                            title={`Set to ${orig}/admin`}
                          >
                            {orig}/admin
                          </button>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="space-y-1">
                    <Label className="text-[11px] text-foreground font-medium">
                      Password <span className="text-destructive">*</span>
                    </Label>
                    <div className="relative">
                      <Input
                        type={showAddPassword ? 'text' : 'password'}
                        required
                        placeholder="AdminPassword@123!"
                        value={addForm.password}
                        onChange={(e) => setAddForm({ ...addForm, password: e.target.value })}
                        className="h-8 text-xs pr-8 bg-card"
                      />
                      <button
                        type="button"
                        onClick={() => setShowAddPassword(!showAddPassword)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        tabIndex={-1}
                      >
                        {showAddPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-1 border-t border-border/40">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => {
                      setIsAdding(false);
                      setAddForm({ email: '', password: '', name: '', redirectUrl: '' });
                    }}
                    disabled={addLoading}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" size="sm" className="h-7 text-xs font-medium" disabled={addLoading}>
                    {addLoading ? 'Creating...' : 'Create Admin'}
                  </Button>
                </div>
              </form>
            </div>
          )}

          {/* Administrators List */}
          {admins.length === 0 && !isAdding ? (
            <div className="p-8 text-center flex flex-col items-center justify-center">
              <div className="size-10 rounded-full bg-secondary flex items-center justify-center text-muted-foreground mb-2">
                <UserPlus className="size-5" />
              </div>
              <p className="font-heading text-xs font-medium text-foreground mb-0.5">
                No application administrators configured
              </p>
              <p className="font-sans text-[11px] text-muted-foreground  mb-3">
                Create an admin account to allow secure server-to-server administrator verification for this application.
              </p>
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setIsAdding(true)}>
                <Plus className="size-3.5 mr-1" />
                Add First Admin
              </Button>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {admins.map((admin) => (
                <div key={admin.id} className="p-3 transition-colors hover:bg-secondary/20">
                  {editingId === admin.id ? (
                    /* Inline Edit Form */
                    <form onSubmit={handleEditSubmit} className="space-y-3">
                      <div className="flex items-center justify-between pb-1">
                        <span className="font-heading text-xs font-semibold text-foreground">
                          Edit Administrator
                        </span>
                        <Badge variant={editForm.isActive ? 'success' : 'destructive'} className="text-[10px]">
                          {editForm.isActive ? 'Active' : 'Disabled'}
                        </Badge>
                      </div>

                      <div className="grid sm:grid-cols-2 gap-3">
                        <div className="space-y-1">
                          <Label className="text-[11px] text-foreground">Name</Label>
                          <Input
                            value={editForm.name}
                            onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                            className="h-8 text-xs bg-card"
                          />
                        </div>

                        <div className="space-y-1">
                          <Label className="text-[11px] text-foreground">Email *</Label>
                          <Input
                            type="email"
                            required
                            value={editForm.email}
                            onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                            className="h-8 text-xs bg-card"
                          />
                        </div>

                        <div className="space-y-1">
                          <div className="flex items-center justify-between">
                            <Label className="text-[11px] text-foreground">Redirect URL *</Label>
                            {candidateOrigins.length > 0 && (
                              <span className="text-[10px] text-muted-foreground font-sans">Must match app origin</span>
                            )}
                          </div>
                          <Input
                            required
                            value={editForm.redirectUrl}
                            onChange={(e) => setEditForm({ ...editForm, redirectUrl: e.target.value })}
                            className="h-8 text-xs font-mono bg-card"
                          />
                          {candidateOrigins.length > 0 && (
                            <div className="flex flex-wrap items-center gap-1 pt-0.5">
                              <span className="text-[10px] text-muted-foreground font-sans">Quick fill:</span>
                              {candidateOrigins.map((orig) => (
                                <button
                                  key={orig}
                                  type="button"
                                  className="text-[10px] font-mono bg-secondary hover:bg-secondary/80 border border-border px-1.5 py-0.5 rounded text-foreground transition-colors cursor-pointer"
                                  onClick={() => setEditForm((prev) => ({ ...prev, redirectUrl: `${orig}/admin` }))}
                                  title={`Use ${orig}/admin`}
                                >
                                  {orig}/admin
                                </button>
                              ))}
                            </div>
                          )}
                        </div>

                        <div className="space-y-1">
                          <Label className="text-[11px] text-foreground">Password (leave blank to keep)</Label>
                          <div className="relative">
                            <Input
                              type={showEditPassword ? 'text' : 'password'}
                              placeholder="New password (optional)"
                              value={editForm.password}
                              onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                              className="h-8 text-xs pr-8 bg-card"
                            />
                            <button
                              type="button"
                              onClick={() => setShowEditPassword(!showEditPassword)}
                              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                              tabIndex={-1}
                            >
                              {showEditPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                            </button>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-1 border-t border-border/40">
                        <label className="flex items-center gap-2 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            checked={editForm.isActive}
                            onChange={(e) => setEditForm({ ...editForm, isActive: e.target.checked })}
                            className="size-3.5 rounded border-border text-primary focus:ring-primary"
                          />
                          <span className="font-sans text-xs text-foreground">Account Active</span>
                        </label>

                        <div className="flex gap-2">
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={() => setEditingId(null)}
                            disabled={editLoading}
                          >
                            Cancel
                          </Button>
                          <Button type="submit" size="sm" className="h-7 text-xs font-medium" disabled={editLoading}>
                            {editLoading ? 'Saving...' : 'Save Changes'}
                          </Button>
                        </div>
                      </div>
                    </form>
                  ) : (
                    /* Read-Only Row */
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <div className="size-8 rounded bg-secondary border border-border flex items-center justify-center shrink-0">
                          {admin.isActive ? (
                            <CheckCircle2 className="size-4 text-emerald-500" />
                          ) : (
                            <XCircle className="size-4 text-destructive" />
                          )}
                        </div>

                        <div className="min-w-0 flex-1 grid sm:grid-cols-3 gap-2 items-center">
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <span className="font-sans text-xs font-medium text-foreground truncate">
                                {admin.name || admin.email.split('@')[0]}
                              </span>
                              <Badge
                                variant={admin.isActive ? 'success' : 'destructive'}
                                className="text-[10px] px-1.5 py-0 shrink-0"
                              >
                                {admin.isActive ? 'Active' : 'Inactive'}
                              </Badge>
                              <Badge
                                variant="outline"
                                className={admin.totpEnabled ? 'text-[10px] px-1.5 py-0 shrink-0 bg-emerald-500/10 text-emerald-500 border-emerald-500/30' : 'text-[10px] px-1.5 py-0 shrink-0 bg-secondary text-muted-foreground border-border'}
                              >
                                {admin.totpEnabled ? '2FA Active' : '2FA Off'}
                              </Badge>
                            </div>
                            <span className="font-mono text-[11px] text-muted-foreground truncate block">
                              {admin.email}
                            </span>
                          </div>

                          <div className="min-w-0">
                            <div className="flex items-center gap-1 text-[11px] text-muted-foreground truncate">
                              <Globe className="size-3 shrink-0 text-muted-foreground/70" />
                              <span className="font-mono truncate" title={admin.redirectUrl}>
                                {admin.redirectUrl}
                              </span>
                            </div>
                          </div>

                          <div className="text-[11px] text-muted-foreground">
                            <span>Logins: <strong className="text-foreground">{admin.loginCount || 0}</strong></span>
                            {admin.lastLoginAt && (
                              <span className="ml-2 text-[10px] text-muted-foreground/80">
                                ({new Date(admin.lastLoginAt).toLocaleDateString()})
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-7 rounded text-muted-foreground hover:text-foreground"
                          onClick={() => handleStartEdit(admin)}
                          title="Edit administrator"
                        >
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-7 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                          onClick={() => setDeletingAdmin(admin)}
                          title="Delete administrator"
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deletingAdmin} onOpenChange={(open) => !open && setDeletingAdmin(null)}>
        <DialogContent className="sm:max-w-[420px] w-full">
          <DialogHeader>
            <DialogTitle className="font-heading text-foreground">Remove Application Admin</DialogTitle>
            <DialogDescription className="font-sans text-xs text-muted-foreground">
              Are you sure you want to remove <strong className="text-foreground">{deletingAdmin?.email}</strong> from{' '}
              <strong className="text-foreground">{clientName || 'this application'}</strong>? They will immediately lose
              access to the application&apos;s admin dashboard.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="mt-3">
            <Button variant="outline" size="sm" onClick={() => setDeletingAdmin(null)} disabled={deleteLoading}>
              Cancel
            </Button>
            <Button variant="destructive" size="sm" onClick={handleDelete} disabled={deleteLoading}>
              {deleteLoading ? 'Removing...' : 'Remove Admin'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

// Backward-compatibility export so any old imports don't break
export const ProvisionAdminModal = AppAdminManager;
export default AppAdminManager;
