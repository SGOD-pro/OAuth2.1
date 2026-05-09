import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller.js';
import { CorsCacheService } from './cors-cache.service.js';
import { AuthConfigModule } from '../utils/auth.module.js';
import { DatabaseModule } from '../database/database.module.js';

/**
 * Admin module — admin-only routes for OAuth client management.
 *
 * Imports:
 *   AuthConfigModule — resolves AUTH_INSTANCE injection token
 *   DatabaseModule   — resolves MongoService for stats + logs queries
 *
 * Providers:
 *   CorsCacheService — injected into AdminController for cache invalidation
 */
@Module({
  imports: [AuthConfigModule, DatabaseModule],
  controllers: [AdminController],
  providers: [CorsCacheService],
})
export class AdminModule {}
