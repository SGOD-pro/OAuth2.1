import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Req,
  Param,
  Body,
  Inject,
  UnauthorizedException,
  InternalServerErrorException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AUTH_INSTANCE } from '../utils/auth.js';
import type { AuthInstance } from '../utils/auth.js';
import { CorsCacheService } from './cors-cache.service.js';
import { MongoService } from '../database/mongo.service.js';

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * Admin Controller
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Every route is protected by requireAdmin() which verifies:
 *   1. A valid Better Auth session exists
 *   2. session.user.role === 'admin'
 *
 * OAuth Provider API calls:
 *   The @better-auth/oauth-provider plugin adds methods to auth.api
 *   at runtime. We cast to `any` because the static AuthInstance type
 *   doesn't include plugin-contributed methods.
 *
 *   Method names used here are prefixed with TODO where their exact
 *   signatures could not be confirmed from source. Verify against
 *   @better-auth/oauth-provider docs before production.
 */
@Controller('api/admin')
export class AdminController {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly authApi: any;

  constructor(
    @Inject(AUTH_INSTANCE)
    private readonly auth: AuthInstance,
    private readonly corsCache: CorsCacheService,
    private readonly mongo: MongoService,
  ) {
    this.authApi = auth.api;
  }

  // ── Auth guard ────────────────────────────────────────────────────
  private async requireAdmin(req: Request): Promise<void> {
    const session = await this.auth.api.getSession({
      headers: req.headers as Record<string, string>,
    });

    if (!session || !session.user) {
      throw new UnauthorizedException('Authentication required');
    }

    if ((session.user as Record<string, unknown>).role !== 'admin') {
      throw new UnauthorizedException('Admin access required');
    }
  }

  // ── POST /admin/clients ──────────────────────────────────────────
  /**
   * Register a new OAuth client.
   *
   * Body: {
   *   client_name: string
   *   redirect_uris: string[]
   *   allowed_origins: string[]
   *   skip_consent: boolean
   *   enable_end_session: boolean
   * }
   *
   * Returns { client_id, client_secret, ... }
   * client_secret is returned ONCE — never again after this call.
   *
   * TODO: verify exact method name — `adminCreateOAuthClient` is the
   *   observed name from @better-auth/oauth-provider runtime inspection.
   *   Confirm against upstream docs/source.
   */
  @Post('clients')
  async createClient(
    @Req() req: Request,
    @Body() body: Record<string, unknown>,
  ): Promise<unknown> {
    await this.requireAdmin(req);

    // TODO: verify exact method name from @better-auth/oauth-provider
    const result = await this.authApi.adminCreateOAuthClient({
      headers: req.headers as Record<string, string>,
      body: {
        client_name: body.client_name as string,
        redirect_uris: body.redirect_uris as string[],
        allowed_origins: body.allowed_origins as string[],
        skip_consent: (body.skip_consent as boolean) ?? false,
        enable_end_session: (body.enable_end_session as boolean) ?? true,
      },
    });

    // Invalidate entire CORS cache — new client's origins must work immediately
    this.corsCache.invalidate();

    return result;
  }

  // ── GET /admin/clients ───────────────────────────────────────────
  /**
   * List all registered OAuth clients.
   *
   * TODO: verify exact method name from @better-auth/oauth-provider
   */
  @Get('clients')
  async listClients(@Req() req: Request): Promise<unknown> {
    await this.requireAdmin(req);

    // TODO: verify exact method name from @better-auth/oauth-provider
    return this.authApi.getOAuthClients({
      headers: req.headers as Record<string, string>,
    });
  }

  // ── GET /admin/clients/:id ───────────────────────────────────────
  /**
   * Get a single OAuth client by ID.
   *
   * TODO: verify exact method name from @better-auth/oauth-provider
   */
  @Get('clients/:id')
  async getClient(
    @Req() req: Request,
    @Param('id') id: string,
  ): Promise<unknown> {
    await this.requireAdmin(req);

    // TODO: verify exact method name from @better-auth/oauth-provider
    return this.authApi.getOAuthClient({
      headers: req.headers as Record<string, string>,
      params: { id },
    });
  }

  // ── PATCH /admin/clients/:id ─────────────────────────────────────
  /**
   * Update an OAuth client.
   *
   * Body: Partial<{
   *   redirect_uris: string[]
   *   allowed_origins: string[]
   *   skip_consent: boolean
   *   is_active: boolean
   * }>
   *
   * TODO: verify exact method name from @better-auth/oauth-provider
   */
  @Patch('clients/:id')
  async updateClient(
    @Req() req: Request,
    @Param('id') id: string,
    @Body() body: Record<string, unknown>,
  ): Promise<unknown> {
    await this.requireAdmin(req);

    // TODO: verify exact method name from @better-auth/oauth-provider
    const result = await this.authApi.adminUpdateOAuthClient({
      headers: req.headers as Record<string, string>,
      body: {
        client_id: id,
        ...body,
      },
    });

    // Invalidate CORS cache — updated origins take effect immediately
    this.corsCache.invalidate();

    return result;
  }

  // ── DELETE /admin/clients/:id ────────────────────────────────────
  /**
   * Delete an OAuth client.
   *
   * TODO: verify exact method name from @better-auth/oauth-provider
   */
  @Delete('clients/:id')
  async deleteClient(
    @Req() req: Request,
    @Param('id') id: string,
  ): Promise<unknown> {
    await this.requireAdmin(req);

    // TODO: verify exact method name from @better-auth/oauth-provider
    const result = await this.authApi.deleteOAuthClient({
      headers: req.headers as Record<string, string>,
      body: { client_id: id },
    });

    // Invalidate CORS cache — removed client's origins must be blocked immediately
    this.corsCache.invalidate();

    return result;
  }

  // ── GET /admin/stats ─────────────────────────────────────────────
  /**
   * Return service-level stats by querying MongoDB directly.
   *
   * Better Auth collection names (MongoDB adapter):
   *   user        — registered users
   *   oauthClient — registered OAuth clients
   *   session     — active sessions (proxy for recent logins)
   *
   * Returns: { totalClients, activeClients, totalUsers, recentLogins }
   */
  @Get('stats')
  async getStats(@Req() req: Request): Promise<{
    totalClients: number;
    activeClients: number;
    totalUsers: number;
    recentLogins: number;
  }> {
    await this.requireAdmin(req);

    try {
      const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

      const [totalUsers, totalClients, activeClients, recentLogins] =
        await Promise.all([
          this.mongo.collection('user').countDocuments(),
          this.mongo.collection('oauthClient').countDocuments(),
          this.mongo.collection('oauthClient').countDocuments({ disabled: { $ne: true } }),
          // Using session collection as a proxy for recent logins.
          // Better Auth does not maintain a separate audit log collection.
          // Sessions created in the last 24h represent unique login events.
          this.mongo.collection('session').countDocuments({
            createdAt: { $gte: since24h },
          }),
        ]);

      return { totalUsers, totalClients, activeClients, recentLogins };
    } catch (err) {
      throw new InternalServerErrorException(
        `Failed to query stats: ${String(err)}`,
      );
    }
  }

  // ── GET /admin/logs ──────────────────────────────────────────────
  /**
   * Return recent activity logs.
   *
   * Better Auth does not maintain a built-in audit log collection.
   * We return the last 100 sessions as a proxy for recent login activity.
   * Each session record contains: userId, createdAt, ipAddress, userAgent.
   *
   * Fields returned:
   *   userId, userEmail (joined from user collection), action, ipAddress, createdAt
   *
   * If a dedicated audit collection is added in the future, replace this
   * query with a direct query on that collection.
   */
  @Get('logs')
  async getLogs(@Req() req: Request): Promise<unknown[]> {
    await this.requireAdmin(req);

    try {
      // Fetch last 100 sessions sorted newest-first
      const sessions = await this.mongo
        .collection('session')
        .find({})
        .sort({ createdAt: -1 })
        .limit(100)
        .toArray();

      // Join with user collection for email enrichment
      const userIds = [...new Set(sessions.map((s) => s['userId']))].filter(Boolean);
      const users = await this.mongo
        .collection('user')
        .find({ _id: { $in: userIds } })
        .toArray();

      const userEmailMap = new Map(
        users.map((u) => [String(u['_id']), u['email']]),
      );

      return sessions.map((s) => ({
        userId: s['userId'],
        userEmail: userEmailMap.get(String(s['userId'])) ?? null,
        // Sessions represent 'sign_in' actions.
        // Enhance with a real audit log collection for richer action types.
        action: 'sign_in',
        ipAddress: s['ipAddress'] ?? null,
        createdAt: s['createdAt'],
      }));
    } catch (err) {
      throw new InternalServerErrorException(
        `Failed to query logs: ${String(err)}`,
      );
    }
  }
}
