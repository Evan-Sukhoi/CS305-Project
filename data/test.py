import re

a = '1112-0'

print(bool(re.match(r'^\d+-\d+$', a)))
