import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';
import helmet from 'helmet';
import { DynamicCorsMiddleware } from './middleware/dynamic-cors.middleware.js';
import { MongoService } from './database/mongo.service.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bodyParser: false,
  });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Fix 2 — CORS is handled by DynamicCorsMiddleware
  // registered globally here to run BEFORE BetterAuth.
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  const mongoService = app.get(MongoService);
  const dynamicCorsMiddleware = new DynamicCorsMiddleware(mongoService);
  app.use(dynamicCorsMiddleware.use.bind(dynamicCorsMiddleware));

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // Security headers via helmet
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          connectSrc: ["'self'", 'https://accounts.google.com'],
        },
      },
      hsts: { maxAge: 31536000, includeSubDomains: true },
    }),
  );

  // app.enableCors({
  //   origin: true,
  //   credentials: true,
  // });

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // DO NOT use app.enableCors() here.
  // The DynamicCorsMiddleware is registered above.
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
