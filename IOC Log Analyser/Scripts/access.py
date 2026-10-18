import re as r
import os


def access(File):
    line = []

    pathway = [os.path.join(File, f) for f in os.listdir(File) if f.startswith("access")]
    for path in pathway:
        with open(path, "r") as fail:
            for i in fail:
                line.append(i)
    return line

def BadIP(File):

    malicious = []
    line = access(File)
    ioc = [os.path.join(File, f) for f in os.listdir(File) if f.startswith("ioc")]
    ip = r.compile(r"(\d{1,3}\.){3}\d{1,3}")
    for file in ioc:
        with open(file, "r") as bad:
            for error in bad:
                error = error.strip()
                if ip.match(error):
                    for log in line:
                        if error in log:
                            malicious.append(log)

    return malicious


def BadPath(File):

    Pathway = []
    line = access(File)
    ioc = [os.path.join(File, f) for f in os.listdir(File) if f.startswith("ioc")]

    for file in ioc:
        with open(file, "r") as bad:
            for error in bad:
                error = error.strip()
                if error.startswith("/"):
                    for log in line:
                        if error in log:
                            Pathway.append(log)

    return Pathway

