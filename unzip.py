import zipfile
import os

def find_next_zip(filename):
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith(".zip"):
                return file
    return None

def unzip_recursive(filename):
    while filename:
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall()
            filename = find_next_zip(filename)

if __name__ == "__main__":
    start_file = "834.zip"
    unzip_recursive(start_file)
