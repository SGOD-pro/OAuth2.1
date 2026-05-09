import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MongoClient, Db, Collection } from 'mongodb';

/**
 * Raw MongoDB access provider for middleware and services
 * that need direct DB queries outside of Better Auth.
 *
 * Shares the same connection URI as Better Auth but maintains
 * its own client instance for independent lifecycle management.
 */
@Injectable()
export class MongoService {
  private client: MongoClient;
  private db: Db;
  private connected = false;

  constructor(private readonly config: ConfigService) {
    const mongoUri = this.config.get<string>('MONGO_URI');
    if (!mongoUri) {
      throw new Error('MONGO_URI is not set');
    }

    this.client = new MongoClient(mongoUri);
    this.db = this.client.db();

    void this.client.connect().then(() => {
      this.connected = true;
    }).catch((error) => {
      console.error('MongoService: Failed to connect to MongoDB:', error);
      process.exit(1);
    });
  }

  /**
   * Get a typed collection reference.
   */
  collection<T extends Document = Document>(name: string): Collection<T> {
    return this.db.collection<T>(name);
  }

  /**
   * Check if the database connection is alive.
   */
  isConnected(): boolean {
    return this.connected;
  }

  /**
   * Graceful shutdown.
   */
  async onModuleDestroy(): Promise<void> {
    await this.client.close();
  }
}
