import type {
    Context,
    Next,
} from "hono";

import { config }
    from "../config";

import {
    originCache,
} from "../cache/origin-cache";

import { getDb } from "../db/mongo";

export async function isOriginAllowed(origin: string): Promise<boolean> {
    const database = await getDb();
    const client = await database.collection("oauthClient").findOne({
        redirectUris: {
            $elemMatch: {
                $regex: `^${escapeRegex(origin)}`,
            },
        },
    });

    return Boolean(client);
}

function applyCorsHeaders(
    c: Context,
    origin: string
) {
    c.header(
        "Access-Control-Allow-Origin",
        origin
    );

    c.header(
        "Access-Control-Allow-Credentials",
        "true"
    );

    c.header(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );

    c.header(
        "Access-Control-Allow-Headers",
        "Content-Type,Authorization"
    );
}

function applyCorsHeadersToResponse(
    c: Context,
    origin: string
) {
    c.res.headers.set(
        "Access-Control-Allow-Origin",
        origin
    );
    c.res.headers.set(
        "Access-Control-Allow-Credentials",
        "true"
    );
    c.res.headers.set(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
    c.res.headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type,Authorization"
    );
}

export async function dynamicCors(
    c: Context,
    next: Next
) {
    const origin =
        c.req.header("origin");

    const ownFrontend =
        config.frontendUrl;

    // Allow internal frontend
    if (
        !origin ||
        origin === ownFrontend
    ) {
        applyCorsHeaders(c, origin || ownFrontend);

        if (c.req.method === "OPTIONS") {
            return c.body(null, 204);
        }

        await next();
        applyCorsHeadersToResponse(c, origin || ownFrontend);
        return;
    }

    // Cache lookup
    let allowed =
        originCache.get(origin);

    // Cache miss
    if (allowed === undefined) {
        try {
            allowed =
                await isOriginAllowed(origin);

            originCache.set(
                origin,
                allowed
            );
        } catch {
            allowed = false;
        }
    }

    if (!allowed) {
        return c.json({
            error:
                "Origin not allowed",
        }, 403);
    }

    applyCorsHeaders(c, origin);

    if (c.req.method === "OPTIONS") {
        return c.body(null, 204);
    }

    await next();
    applyCorsHeadersToResponse(c, origin);
}

function escapeRegex(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}