#!/usr/bin/env bash
set -ex

version_file="dragoneye/version.py"

git config --local user.email "action@github.com"
git config --local user.name "GitHub Action"
git fetch --tags
latest_tag=$(git describe --tags `git rev-list --tags --max-count=1`)
echo "latest tag: $latest_tag"
echo "__version__ = '$latest_tag'" > $version_file

git commit --reuse-message=HEAD $version_file || echo "No changes to commit"
git push origin
