import {
  All,
  Controller,
  Inject,
  Req,
  Res,
} from '@nestjs/common';

import type { Request, Response } from 'express';

import { toNodeHandler } from 'better-auth/node';

import { AUTH_INSTANCE } from './utils/auth';
import type { AuthInstance } from './utils/auth';

@Controller('/api/auth')
export class AppController {
  private authHandler:
    ReturnType<typeof toNodeHandler>;

  constructor(
    @Inject(AUTH_INSTANCE)
    private readonly auth: AuthInstance,
  ) {
    this.authHandler =
      toNodeHandler(auth);
  }

  @All('*path')
  async handler(
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const appName =
      req.headers['x-app-name'];

    const appVersion =
      req.headers['x-app-version'];

    console.log({
      appName,
      appVersion,
      path: req.path,
      ip: req.ip,
      userAgent:
        req.headers['user-agent'],
    });

    return this.authHandler(req, res);
  }
}