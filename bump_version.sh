#!/usr/bin/env bash
set -ex

version_file="version.py"

git config --local user.email "action@github.com"
git config --local user.name "GitHub Action"
git fetch --tags
latest_tag=$(git describe --tags `git rev-list --tags --max-count=1`)
echo "latest tag: $latest_tag"
new_tag=$(echo $latest_tag | awk -F. -v a="$1" -v b="$2" -v c="$3" '{printf("%d.%d.%d", $1+a, $2+b , $3+1)}')
echo "new tag: $new_tag"

# Update __version__ in python
echo "__version__ = '$new_tag'" > $version_file

git commit --reuse-message=HEAD $version_file || echo "No changes to commit"
git push origin
# Commenting the rest of this out because we use the release drafter to actually push new tagsz
#git tag $new_tag
#git push origin $new_tag
#RELEASE_NOTE=$(git log -1 --pretty=%B)
#gh release create $new_tag -t $new_tag --repo $repo -n "$RELEASE_NOTE"