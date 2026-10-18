import re  as r
from collections import Counter
import os 



def Failed_pass(File):

    pathway = [os.path.join(File, f) for f in os.listdir(File) if f.startswith("auth")]
    finder = r.compile(r"\bFailed Password\b", r.IGNORECASE)
    ip = r.compile(r"(\d{1,3}\.){3}\d{1,3}")
    Con = []
    for path in pathway:
        with open(path, "r") as f:
            for i in f:
                P = ip.search(i)
                if finder.search(i) and P:
                    Con.append(P.group())
                    Hi = Counter(Con)
    return Hi
