import os
import re

# Define the regex pattern
pattern = r'(NT[A-Z]+)\n(\w+)\n(\w+)\n(\w+)\('

# Get the current directory
current_directory = os.getcwd()

# Iterate through all files in the current directory
count=0
for file_name in os.listdir(current_directory):
    # Check if the file is a .h file
    count+=1
    contents=[]
    if file_name.endswith('.h'):
        print(f"processing {file_name}")
        f = open(file_name,'r')
        contents = f.readlines()
        f.close()
        c = []
        for line in contents:
            c.append(line)
            searchcontent = c[-4:]
            occurrence = re.search(pattern, "".join(searchcontent))
            if occurrence:
                c=c[:-4]
                searchcontent[0] = searchcontent[0].replace(occurrence.group(1),"typedef")
                searchcontent[1] = searchcontent[1].replace(occurrence.group(2),occurrence.group(2)+"(")
                searchcontent[2] = searchcontent[2].replace(occurrence.group(3),occurrence.group(3)+"*")
                searchcontent[3] = searchcontent[3].replace(occurrence.group(4),occurrence.group(4).upper()+")")
                c = c + searchcontent
        f = open(file_name,"w")
        f.write("".join(c))
        f.close()