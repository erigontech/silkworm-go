#!/bin/bash

set -e
set -u
set -o pipefail

SRC_GIT_URL="https://github.com/erigontech/silkworm.git"
TARGET="silkworm_capi"
FINAL_LIB_COUNT=3

function release_version {
	version="$1"
	version=${version#release/} # cut prefix
	version=${version%-base}    # cut suffix
	echo "$version"
}

function os_name {
	value=$(uname -s)
	case $value in
		Linux)
			echo linux;;
		Darwin)
			echo macos;;
		*)
			echo "unsupported OS: $value"
			exit 1;;
	esac
}

function arch_name {
	value=$(uname -m)
	case $value in
		arm64)
			echo arm64;;
		aarch64)
			echo arm64;;
		x86_64)
			echo x64;;
		*)
			echo "unsupported CPU architecture: $value"
			exit 1;;
	esac
}

work_dir="$1"
make_jobs="$2"
base_tag="$3"

checkout_dir="$work_dir/silkworm-go"
project_dir="$work_dir/silkworm"
build_dir="$work_dir/build"
product_dir="$build_dir/silkworm/capi"
version=$(release_version "$base_tag")
release_branch="release/$version"

function checkout {
	src_tag="capi-$version"
	echo "checkout tag $src_tag to $project_dir ..."
	git clone --branch "$src_tag" --depth 1 \
		--recurse-submodules \
		--config submodule.ethereum-tests.update=none \
		--config submodule.LegacyTests.update=none \
		"$SRC_GIT_URL" "$project_dir"
	echo "checkout done"
	echo
}

function install_cmake {
	cmake_version=3.27.8
	case $(os_name) in
		macos)
			mkdir -p "$work_dir/cmake"
			cd "$work_dir/cmake"
			curl -L --output cmake.tgz "https://github.com/Kitware/CMake/releases/download/v${cmake_version}/cmake-${cmake_version}-macos-universal.tar.gz"
			tar xzf cmake.tgz
			mv cmake-*/CMake.app .
			export "PATH=$work_dir/cmake/CMake.app/Contents/bin:$PATH"
			;;
		*)
			echo "install_cmake not implemented"
			exit 1
			;;
	esac
}

function build_setup {
	echo "build_setup..."

	pip3 install --user --disable-pip-version-check conan==1.62.0 chardet
	conan_path="$(python3 -m site --user-base)/bin"
	export "PATH=$conan_path:$PATH"
	conan --version

	if ! which cmake > /dev/null
	then
		install_cmake
	fi
	cmake --version

	echo "build_setup done"
	echo
}

function build {
	echo "build target $TARGET in $build_dir ..."
	cmake -B "$build_dir" -S "$project_dir"
	cmake --build "$build_dir" --target "$TARGET" --parallel "$make_jobs"
	ls -l "$product_dir/"*$TARGET*
	echo "build done"
	echo
}

function build_fake {
	echo "build_fake target $TARGET in $build_dir ..."
	case $(os_name) in
		linux)
			product_file_ext=so ;;
		macos)
			product_file_ext=dylib ;;
	esac
	mkdir -p "$product_dir"
	echo hello > "$product_dir/lib${TARGET}.$product_file_ext"
	ls -l "$product_dir/"*$TARGET*
	echo "build_fake done"
	echo
}

function upload {
	product_path=$(echo "$product_dir/"*$TARGET*)
	product_file_name=$(basename "$product_path")
	echo "upload $product_file_name to $release_branch branch ..."

	upload_dir_name="$(os_name)_$(arch_name)"
	upload_dir_path="$checkout_dir/lib/$upload_dir_name"
	mkdir -p "$upload_dir_path"
	cp "$product_path" "$upload_dir_path"

	cd "$checkout_dir"
	git fetch origin "$release_branch"
	if [[ "$(git rev-parse --abbrev-ref HEAD)" != "$release_branch" ]]
	then
		git checkout --track "origin/$release_branch"
	fi
	git pull
	git add lib
	git config user.name GitHub
	git config user.email noreply@github.com
	git commit -m "$upload_dir_name/$product_file_name"
	git push

	echo "upload done"
	echo
}

function finalize {
	echo "finalize..."
	cd "$checkout_dir"

	lib_count=$(($(ls -1 lib | wc -l) - 1))
	if [[ $lib_count != $FINAL_LIB_COUNT ]]
	then
		echo "finalize skipped, waiting for $(( $FINAL_LIB_COUNT - $lib_count )) more builder(s)"
		echo
		return
	fi

	cp "$project_dir/silkworm/capi/silkworm.h" include/
	git add include
	git commit -m 'include'
	git push

	git tag --delete "$base_tag"
	git push --delete origin "$base_tag"
	git push --delete origin "$release_branch"

	git tag "v$version"
	git push origin "v$version"

	echo "finalize done"
	echo
}

checkout
build_setup
build
#build_fake
upload
finalize
