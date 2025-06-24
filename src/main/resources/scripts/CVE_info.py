import argparse
import shutil
import subprocess


def get_cve_info():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File with CVE", required=True)
    args = parser.parse_args()
    cvemap_command = shutil.which('cvemap')
    if cvemap_command is not None:
        with open(args.file, "r") as f:
            for line in f:
                param = line.strip()
                if param:
                    try:
                        result = subprocess.run([cvemap_command, "-id", param], capture_output=True, text=True)
                        print(result.stdout)
                    except Exception as e:
                        print(f"Error occurred {param}: {e}")


if __name__ == '__main__':
    get_cve_info()
