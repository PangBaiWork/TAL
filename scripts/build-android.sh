#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOCAL_BIN="${LOCAL_BIN:-$HOME/.local/bin}"

if ! command -v cmake >/dev/null 2>&1 || ! command -v ninja >/dev/null 2>&1; then
  if [ -x "$LOCAL_BIN/cmake" ] && [ -x "$LOCAL_BIN/ninja" ]; then
    :
  else
    python3 -m pip install --user cmake ninja
  fi
fi

export PATH="$LOCAL_BIN:$PATH"

if [ -z "${ANDROID_NDK:-}" ]; then
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    ANDROID_NDK=$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)
  elif [ -n "${ANDROID_SDK_ROOT:-}" ] && [ -d "$ANDROID_SDK_ROOT/ndk" ]; then
    ANDROID_NDK=$(find "$ANDROID_SDK_ROOT/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)
  else
    echo "ANDROID_NDK is not set and no NDK was found under ANDROID_HOME or ANDROID_SDK_ROOT." >&2
    exit 1
  fi
  export ANDROID_NDK
fi

cmake --preset android-arm64-release "$ROOT_DIR"
cmake --build --preset android-arm64-release
