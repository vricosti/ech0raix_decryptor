import sys
import os
import platform
import datetime


def creation_date(path_to_file):
    """
    Try to get the date that a file was created, falling back to when it was
    last modified if that isn't possible.
    See http://stackoverflow.com/a/39501288/1709587 for explanation.
    """
    if platform.system() == 'Windows':
        return os.path.getctime(path_to_file)
    else:
        try:
            stat = os.stat(path_to_file)
            try:
                return stat.st_birthtime
            except AttributeError:
                # We're probably on Linux. No easy way to get creation dates here,
                # so we'll settle for when its content was last modified.
                return stat.st_mtime
        except FileNotFoundError:
            return None


def main(start_path):
    if start_path == '.' or start_path == './':
        cur_path = os.path.dirname(os.path.realpath(__file__))
        start_path = cur_path

    for dirpath, subdirs, files in os.walk(start_path, followlinks=True):
         for file in files:
             filepath = os.path.join(dirpath, file)
             if os.path.exists(filepath):
                date = creation_date(filepath)
                if date:
                    dt = datetime.datetime.fromtimestamp(date)
                    if not file.endswith('.encrypt'):
                        if dt.day == 14 and dt.month == 6 and dt.year == 2022:
                            print("Found file with corresponding date {}".format(filepath))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Missing path argument")

    main(sys.argv[1])