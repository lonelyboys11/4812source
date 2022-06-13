
from os import walk

# Add Windows directory that contain malware samples
samplesDirectories = ["D:/User/Me/Documents/2022 Semester 1/Thesis/Malware Samples/APTMalware-master/APTMalware-master/samples", "D:/User/Me/Documents/2022 Semester 1/Thesis/Malware Samples/theZoo-master/malware/Binaries", "D:/User/Me/Documents/2022 Semester 1/Thesis/Malware Samples/theZoo-master/malware/Source/Original", "D:/User/Me/Documents/2022 Semester 1/Thesis/Malware Samples/theZoo-master/malware/Source/Reversed"]

malwareSamples = []
malwareDirSamples = []
APTMalware = []
libraryArray = []

for path in samplesDirectories:
    for (dirPath, dirNames, fileNames) in walk(path):
        malwareSamples.extend(fileNames)
        malwareDirSamples.extend(dirNames)
        break

for i in range(len(malwareSamples)):
    malwareSamples[i] = malwareSamples[i]

for i in range(len(malwareDirSamples)):
    malwareDirSamples[i] = malwareDirSamples[i]

# Show list of malwares being searched through
print(malwareDirSamples)
print(malwareSamples)

library = open("APTICS.txt")
for malware in library.readlines():
    libraryArray.append(malware.strip())

library.close()
matches = []

for sample in libraryArray:
    if any(sample in substring for substring in malwareDirSamples):
        matches.append(sample)
        print("Sample related to APT on ICS found: ", sample)

for sample in malwareSamples:
    if any(sample in substring for substring in libraryArray):
        matches.append(sample)
        print("Sample related to APT on ICS found: ", sample)

with open("Classification.txt") as classification:
    text = classification.read()

classificationArray = text.split('#')
classificationArray.pop(0) #Remove first element that is empty
submodules = []

for array in classificationArray:
    desc = array.split('\n')
    characs = ""
    for i in range(50 - int(0.5*len(desc[0]))):
        characs += '='
    print('\n' + characs + desc[0] + characs)
    submodules.append(desc[0])
    desc.pop(-1) # Remove empty last element

    for info in desc:

        if info[0] == '!':
            # brief description
            info = info.replace('!', '')
            print(info)

        if info[0] == '@':
            # ATT&CK Tactic and Technique information
            info = info.replace('@', '')
            tactics = info.split(',')
            print("\n{0:28} {1}\n".format("Tactic", "Technique"))
            for tac in tactics:
                tac = tac.split(":")
                print("{0:28} {1}".format(tac[0], tac[1]))
            print("\n")

        if info[0] == '&':
            # Associated names
            info = info.replace('&', '')
            info = info.replace(',', ', ')
            print("{0:28} {1}".format("Associated Name(s):", info))

        if info[0] == '%':
            # Assiciated group(s)
            info = info.replace('%', '')
            info = info.replace(',', ', ')
            print("{0:28} {1}".format("Associated APT Group(s):", info))

        if info[0] == '^':
            # Relevant ICS sector
            info = info.replace('^', '')
            info = info.replace(',', ', ')
            print("{0:28} {1}".format("Relevant ICS sector:", info))

        if info[0] == '$':
            # Method available
            info = info.replace('$', '')
            info = info.replace(',', ', ')
            print("{0:28} {1}".format("Method available:", info))

    characs = ""
    for i in range(50):
        characs += '='
    print('\n' + characs + characs)


#  Combining submodules to create an APT attack framework
for i in range(0,len(submodules)):
    print("{0:10}: {1}".format(i, submodules[i]))
selected = input("\nSelect submodules to include in APT framework (e.g. 2,4,6): ")
selected = selected.replace(' ', '')
selected = selected.split(',')
try:
    selected = list(map(int, selected))
except ValueError:
    print("Invalid input. Try numbers separated by commas only")
    exit()

print("\nSelected: ", end='')
for i in range(0, len(selected)):
    try:
        if i == len(selected) - 1:
            print("and " + submodules[selected[i]] + " ", end='')
        else:
            print(submodules[selected[i]] + ", ", end='')
    except IndexError:
        print("Invalid submodule selected")
        exit()

print("as part of APT framework")






