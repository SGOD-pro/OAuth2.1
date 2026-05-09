import { Module, Global } from '@nestjs/common';
import { MongoService } from './mongo.service.js';

/**
 * Global database module — provides MongoService to all modules
 * without requiring explicit imports.
 */
@Global()
@Module({
  providers: [MongoService],
  exports: [MongoService],
})
export class DatabaseModule {}
