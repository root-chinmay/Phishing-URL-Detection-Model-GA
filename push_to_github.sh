#!/bin/bash
# MobiURL-Guard GitHub & Vercel Push Utility
set -e

REPO_URL="https://github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git"
BRANCH="main"

echo "=================================================="
echo "MobiURL-Guard Repository Push & Deployment Script"
echo "Target: $REPO_URL"
echo "=================================================="

TOKEN="${1:-$GITHUB_TOKEN}"

if [ -z "$TOKEN" ]; then
    echo "Usage: ./push_to_github.sh <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>"
    echo "Or set GITHUB_TOKEN environment variable."
    echo ""
    echo "Attempting git push with existing credentials..."
    git push origin "$BRANCH" || {
        echo ""
        echo "Push requires authentication!"
        echo "Please generate a GitHub Personal Access Token (PAT) with 'repo' scope at: https://github.com/settings/tokens"
        echo "Then run: ./push_to_github.sh ghp_yourTokenHere"
        exit 1
    }
else
    AUTH_URL="https://${TOKEN}@github.com/root-chinmay/Phishing-URL-Detection-Model-GA.git"
    echo "Configuring authenticated origin..."
    git remote set-url origin "$AUTH_URL"
    
    echo "Pushing branch $BRANCH to origin..."
    git push -u origin "$BRANCH"
    
    # Restore clean url without token to avoid leaving secret in git config
    git remote set-url origin "$REPO_URL"
    echo "SUCCESS: Code pushed to $REPO_URL on branch $BRANCH!"
    echo "Ready for Vercel deployment: import the repository at https://vercel.com/new"
fi
