import re

test = "this is a -b1- and a -c1-"
vals = re.findall('-..-',test)
sub = 'xxx'
for val in vals:
    print(val[1:3])
    pattern = f"-{val[1:3]}-"
    test = re.sub(pattern,sub,test)
    print(test)
