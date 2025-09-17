print("Called")
import os
print(os.getuid(), "", os.geteuid())
with open("/proc/self/cgroup", "r") as f:
    print(f.read())