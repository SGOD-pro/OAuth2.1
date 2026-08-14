#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e 

echo "🚀 Starting deployment of Hono Backend..."

# Make sure we are in the hono directory
if [ ! -f "template.yaml" ]; then
    echo "❌ Error: Please run this script from inside the 'hono' directory."
    exit 1
fi

echo "📦 Building Hono application..."
npm run build

echo "🏗️ Building AWS SAM package..."
sam build

echo "☁️ Deploying to AWS via SAM..."
# Note: Since you already ran `sam deploy --guided` and saved your config,
# you no longer need the `--guided` flag! SAM will read your samconfig.toml.
sam deploy

echo "✅ Deployment complete!"
