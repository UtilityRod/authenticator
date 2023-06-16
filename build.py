#! /usr/bin/env python3

import os
import contextlib
import argparse
import sys

BUILD_PATH = "./bdir/"
CONFIGURE_COMMAND = "cmake {} ..;"
BUILD_COMMAND = "cmake --build . --clean-first;"

def main():
    parser = argparse.ArgumentParser("Build System", description="Helpful script for build C projects")
    parser.add_argument('-d', '--debug', action="store_true")
    parser.add_argument('-r', '--release', action="store_true")
    args = parser.parse_args(sys.argv[1:])

    if not os.path.exists(BUILD_PATH):
        os.mkdir(BUILD_PATH)

    if args.debug and args.release:
        print("BuildTypeError: debug and release build type must be used seperately")
        return
    elif args.debug:
        configure_command = CONFIGURE_COMMAND.format("-DCMAKE_BUILD_TYPE=Debug")
    elif args.release:
        configure_command = CONFIGURE_COMMAND.format("-DCMAKE_BUILD_TYPE=Release")
    else:
        configure_command = CONFIGURE_COMMAND.format("-DCMAKE_BUILD_TYPE=Standard")

    with pushd(BUILD_PATH):
        os.system(configure_command + BUILD_COMMAND)

@contextlib.contextmanager
def pushd(directory:str) -> None:
    previous_dir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous_dir)


if __name__ == "__main__":
    main()