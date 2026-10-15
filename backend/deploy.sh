#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e 

echo "🚀 Starting deployment of Hono Backend..."

# Make sure we are in the backend directory
if [ ! -f "template.yaml" ]; then
    echo "❌ Error: Please run this script from inside the 'backend' directory."
    exit 1
fi

# Load INTERNAL_GATEWAY_SECRET from environment or local .env if not already set
if [ -z "$INTERNAL_GATEWAY_SECRET" ]; then
    if [ -f ".env" ]; then
        echo "📄 Loading environment variables from backend/.env..."
        set -a
        # shellcheck disable=SC1091
        source .env
        set +a
    elif [ -f "../.env" ]; then
        echo "📄 Loading environment variables from monorepo root .env..."
        set -a
        # shellcheck disable=SC1091
        source ../.env
        set +a
    fi
fi

# Verify INTERNAL_GATEWAY_SECRET presence and minimum length
if [ -z "$INTERNAL_GATEWAY_SECRET" ]; then
    echo "❌ Error: INTERNAL_GATEWAY_SECRET is not set in environment or .env."
    echo "Please set INTERNAL_GATEWAY_SECRET (minimum 32 characters) before deploying."
    exit 1
fi

if [ "${#INTERNAL_GATEWAY_SECRET}" -lt 32 ]; then
    echo "❌ Error: INTERNAL_GATEWAY_SECRET must be at least 32 characters (got ${#INTERNAL_GATEWAY_SECRET})."
    exit 1
fi

echo "📦 Building Hono application..."
npm run build

echo "🏗️ Building AWS SAM package..."
sam build

echo "☁️ Deploying to AWS via SAM with parameter overrides..."
BETTER_AUTH_URL="${BETTER_AUTH_URL:-https://oauth21.vercel.app}"
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-851793713357-efu64vah4peecto0r4l1vnc9ctlpc043.apps.googleusercontent.com}"
FRONTEND_URL="${FRONTEND_URL:-https://oauth21.vercel.app}"

sam deploy \
  --parameter-overrides \
    BetterAuthUrl="${BETTER_AUTH_URL}" \
    GoogleClientId="${GOOGLE_CLIENT_ID}" \
    FrontendUrl="${FRONTEND_URL}" \
    InternalGatewaySecret="${INTERNAL_GATEWAY_SECRET}"

echo "✅ Deployment complete!"
