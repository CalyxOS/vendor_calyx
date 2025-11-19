#!/usr/bin/env python3
# Leads through the process of provisioning YubiHSM for CalyxOS in an offline environment

import glob
import os
import subprocess

OUR_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.getenv("SOURCE_DIRECTORY", OUR_DIR)
OUTPUT_DIR = BASE_DIR


def main():
    extract_sdk()
    install_packages()
    start_connector()
    # hand over to HSM setup script
    subprocess.run([os.path.join(OUR_DIR, "setup.py")])


def extract_sdk():
    # ensure extraction location exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # find SDK files for extraction
    sdk_dir = os.path.join(BASE_DIR, "sdk")
    files = glob.glob('yubihsm2-sdk-*.tar.gz', root_dir=sdk_dir)
    for file in files:
        # extract SDK
        file_path = os.path.join(sdk_dir, file)
        command = ['tar', '-xf', file_path, '-C', OUTPUT_DIR]
        subprocess.run(command, check=True)
    # -dev packages cause issues and aren't needed
    sdk_output_dir = os.path.join(OUTPUT_DIR, "yubihsm2-sdk")
    for f in glob.glob('lib*-dev*.deb', root_dir=sdk_output_dir):
        os.remove(os.path.join(sdk_output_dir, f))


def install_packages():
    print()
    print("This step uses administrator privileges via sudo to install the packages required to provision YubiHSM 2.")
    print("You may be required to enter your administrator password.")
    print()
    input("Press any key to install HSM packages.")
    packages_dir = os.path.join(BASE_DIR, "packages")
    packages_files = [os.path.join(packages_dir, f) for f in glob.glob('*.deb', root_dir=packages_dir)]
    sdk_packages_dir = os.path.join(OUTPUT_DIR, "yubihsm2-sdk")
    sdk_packages_files = [os.path.join(sdk_packages_dir, f) for f in glob.glob('*.deb', root_dir=sdk_packages_dir)]
    command = ['sudo', 'dpkg', '-i'] + packages_files + sdk_packages_files
    subprocess.run(command, check=True)


def start_connector():
    print()
    print("This step uses administrator privileges via sudo to start the YubiHSM connector.")
    print("You may be required to enter your administrator password.")
    print()
    input("Press any key to start the YubiHSM connector.")
    command = ['sudo', 'systemctl', 'start', 'yubihsm-connector']
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
