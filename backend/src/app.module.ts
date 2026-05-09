import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { AuthModule } from '@thallesp/nestjs-better-auth';
import { ConfigModule } from '@nestjs/config';
import { AUTH_INSTANCE } from './utils/auth.js';
import { AuthConfigModule } from './utils/auth.module.js';
import { DatabaseModule } from './database/database.module.js';
import { AdminModule } from './admin/admin.module.js';
import { DynamicCorsMiddleware } from './middleware/dynamic-cors.middleware.js';
import { RequestMethod } from '@nestjs/common';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    DatabaseModule,
    AuthConfigModule,
    AuthModule.forRootAsync({
      imports: [AuthConfigModule],
      inject: [AUTH_INSTANCE],
      useFactory: (auth) => ({ auth }),
    }),
    AdminModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  /**
   * Fix 2 — Register DynamicCorsMiddleware globally.
   *
   * This replaces the hardcoded app.enableCors() that was in main.ts.
   * The middleware checks incoming Origin against allowedOrigins
   * stored in MongoDB's oauthClient collection, backed by an
   * LRU cache with 5-minute TTL.
   *
   * Cache is invalidated on admin client mutations via clearOriginCache().
   */
  configure(consumer: MiddlewareConsumer): void {
    // DynamicCorsMiddleware is now registered in main.ts
    // to ensure it runs before BetterAuth's internal middlewares.
  }
}
