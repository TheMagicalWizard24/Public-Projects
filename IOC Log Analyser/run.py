from Scripts.auth import * 
from Scripts.access import * 

File = os.path.join(os.path.dirname(__file__), "Test-Dataset")


def terminal(File):

    Num = 0
    Fail = Failed_pass(File)

    if not Fail:
        print("No failed-password attempts found.")
        return

    ip, times = Fail.most_common(1)[0]
    for _, count in Fail.items():
        if count >5:
            Num +=1

    print("Below is the access.log results\n ================================")
    print("Below are logs that contain malicous pathways\n")
    print(" ".join(BadPath(File)))

    print("\nBelow are logs that contain malicous IPs")
    print(" ".join(BadIP(File)),"\n ================================")

    print("Below are the results from auth.log\n ===============================")
    print(f"The most common IP -> {ip} had {times} failed password attempts.\n")
    print(f"Their were {Num} total password attempt that failed more then 5 times from diffrent ips")

def report(File):

    BadPATH = BadPath(File)
    BadIp = BadIP(File)
    Failure = Failed_pass(File)
    Num = 0

    if not Failure:
        print("No failed-password attempts found.")
        return

    ip, times = Failure.most_common(1)[0]
    with open("report.txt", "a") as report:

        report.write("Below is the access.log results\n ================================\n")
        report.write("Below are logs that contain malicous pathways\n")
        report.writelines(BadPATH)

        report.write("\nBelow are logs that contain malicous IPs")
        report.writelines(BadIp)        

        report.write("Below are the results from auth.log\n ===============================\n")
        report.write(f"The most common IP -> {ip} had {times} failed password attempts.\n")
        for who, count in Failure.items():
                if count > 5:
                    Num +=1
                    report.write(f"{who} {count}\n")
        report.write(f"Their were {Num} total password attempt that failed more then 5 times from diffrent ips")

report(File)
terminal(File)