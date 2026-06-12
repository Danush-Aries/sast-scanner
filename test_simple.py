# Sample file used as a scan fixture — intentionally vulnerable for demo purposes.
# DO NOT use patterns like this in production code.

import os

# Command injection: variable passed directly to os.system
cmd = "ls"
os.system(cmd)
