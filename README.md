# Arteco Collection Manager

This repository contains the Arteco Collection Manager projects:

- `FineArtApi` (.NET backend)
- `arteco-frontend` (React web)
- `arteco-mobile` (React Native mobile)

Follow the repo setup steps below to push this project to GitHub.

## Local setup

Run these commands in the repository root:

```bash
# install frontend dependencies
cd arteco-frontend
npm install

# run backend
cd ../FineArtApi
dotnet run
```

## Pushing to GitHub

1. Create a new GitHub repo (private or public).
2. Add the remote and push:

```bash
cd "E:/Work/Arteco System/GitHub/arteco-collection-manager"
git remote add origin <GIT_URL>
git branch -M main
git push -u origin main
```

Or, with GitHub CLI:

```bash
gh repo create REPO_NAME --public --source=. --remote=origin --push
```