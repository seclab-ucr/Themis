#!/usr/bin/env python3

import os
import re
import sys


p_new_node = re.compile("Object (\d+) was created\.")
p_del_node = re.compile("Deleting object (\d+) (.*)")


result_dir1 = sys.argv[1]
result_dir2 = sys.argv[2]


def in_whitelist(s1, s2):
    m1 = p_new_node.search(s1)
    m2 = p_new_node.search(s2)
    if m1 and m2:
    #if m1 and m2 and m1.group(1) == m2.group(1) and m1.group(2) != m2.group(2):
        return True
    m1 = p_del_node.search(s1)
    m2 = p_del_node.search(s2)
    if m1 and m2:
    #if m1 and m2 and m1.group(1) == m2.group(1) and m1.group(2) != m2.group(2):
        return True

    return False


f1 = open(os.path.join(result_dir1, 'z3-trace'), 'r')
f2 = open(os.path.join(result_dir2, 'z3-trace'), 'r')

i = 0

while True:
    i += 1
    line1 = f1.readline()
    line2 = f2.readline()
    #print(line1)
    #print(line2)

    s1 = line1
    s2 = line2

    if s1 != s2 and not in_whitelist(s1, s2):
        print("Line %d." % i)
        print(line1)
        print(line2)
        input()

f1.close()
f2.close()

