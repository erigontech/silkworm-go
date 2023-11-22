#!/bin/bash

set -e
set -u
set -o pipefail

SRC_GIT_URL="https://github.com/erigontech/silkworm.git"

function release_version {
	git ls-remote --tags "$SRC_GIT_URL" | grep 'capi-' | cut -d '-' -f 2 | while read version
	do
		if git ls-remote --heads | grep "release/$version" > /dev/null
		then
			continue
		elif git ls-remote --tags | grep "refs/tags/v$version" > /dev/null
		then
			continue
		else 
			echo $version
			break
		fi
	done
}

version=$(release_version)

if [[ -z "$version" ]]
then
	echo "A git tag for a new release is not found in the $SRC_GIT_URL repo. A new tag must have a format: capi-x.y.z"
	exit 1
fi

branch="release/$version"
base_tag="${branch}-base"

echo "release version: $version"
echo "release branch: $branch"
echo "release base tag: $base_tag"

git checkout -b "$branch"
git push --set-upstream origin "$branch"

git tag "$base_tag"
git push origin "$base_tag"
