#!/bin/env python

from sys import argv
from os import walk, path
import requests
import hashlib

params = {
    "VERBOSE": False,
    "RECURSIVE": False,
    "DIRECTORY": False,
    "HIDDEN": False
}

def log(message, level="NOTIFY"):
    if params['VERBOSE'] or level not in ['NOTIFY']:
        print(message)

def usage():
    print("%s : filename_url [files...]" %argv[0])
    return -1

def parse_params():
    global params
    filename = None
    filenames = []
    for index, param in enumerate(argv):
        if index is 0:
            continue
        if param.startswith('-'):
            if '-r' in param:
                params['RECURSIVE'] = True
            elif '-v' in param:
                params['VERBOSE'] = True
            elif '-d' in param:
                params['DIRECTORY'] = True
        else:
            if filename is None:
                filename = param
            else:
                filenames.append(param)
    return filename, filenames

def get_file(parameter):
    output = None
    if '://' in parameter:
        protocol, uri = parameter.split('://')
        if protocol in ['http', 'https']:
            r = requests.get(parameter)
            output = r.text
        else:
            exit('%s : unsupported protocol' %protocol)
    else:
        try:
            with open(parameter) as f:
                return f.read()
        except IsADirectoryError as e:
            log('%s is a directory' %parameter, 'WARNING')
            return None
        except UnicodeDecodeError as e:
            log('%s seems to be a binary file' %parameter, 'WARNING')
    return output

def get_files(directory):
    f = []
    for (dirpath, dirnames, filenames) in walk(directory):
        for filename in filenames:
            if not filename.startswith('.') or params['HIDDEN'] is True:
                f.append(path.join(dirpath, filename))
        for dirname in dirnames:
            if not dirname.startswith('.') or params['HIDDEN'] is True:
                f.extend(get_files(path.join(dirpath, dirname)))
        break
    return f

def hashline(line):
    return hashlib.sha1(line.encode()).hexdigest()[:10]

def extract_significant_code(raw_file):
    codelines = []
    hashes = []
    for line in raw_file.split('\n'):
        codeline = False
        for char in line:
            if char in ";'(){}":
                codeline = True
        if codeline:
            codelines.append(line)
            hashes.append(hashline(line))
    return codelines, hashes

def get_collisions(hashes_a, hashes_b):
    collisions = 0
    for hash in hashes_a:
        if hash in hashes_b:
            collisions += 1
    if len(hashes_a) > 0:
        return collisions, (collisions / len(hashes_a)) * 100
    else:
        return 0, 0

def verify(input_file, output_files):
    raw_file = get_file(input_file)
    if raw_file is None:
        return None
    codelines_a, hashes_a = extract_significant_code(raw_file)
    biggest_collision = ["", 0]
    for index, filename in enumerate(output_files):
        if index > 1:
            log("\t ~ Comparing against %s" %filename)
            raw_file_b = get_file(filename)
            if raw_file_b is not None:
                codelines_b, hashes_b = extract_significant_code(get_file(filename))
                collisions, collision_percentage = get_collisions(hashes_a, hashes_b)
                log("\tCollisions : %s/%s (%s%%)" %(collisions, len(hashes_a), collision_percentage))
                if collision_percentage > biggest_collision[1]:
                    biggest_collision = [filename, collision_percentage]
    log("[Biggest collision is %s (%s%%)]" %(biggest_collision[0], biggest_collision[1]))
    return biggest_collision

def check_similarity(input_name, outputs):
    if params['DIRECTORY'] is True:
        input_files = get_files(input_name)
        output_files = []
        collisions = {}
        collisions_array = []
        for name in outputs:
            output_files.extend(get_files(name))
        for input_file in input_files:
            log('Checking %s for collisions' %input_file)
            file_collisions = verify(input_file, output_files)
            if file_collisions:
                collisions[input_file] = file_collisions
                collisions_array.append([input_file, file_collisions[0], file_collisions[1]])
        return collisions, collisions_array
    else:
        log('Checking %s for collisions' %input_name)
        collision = verify(input_name, outputs)
        if collision is not None:
            return {input_name: collision}, [[input_name, collision[0], collision[1]]]
        else:
            log('%s: invalid filename or URL. Use -d if you want to to use directories' %(input_name), 'ERROR')


def report(collision_obj, collision_array):
    def getKey(item):
        return item[2]
    sorted_array = sorted(collision_array, key=getKey)
    sorted_array.reverse()
    for output in sorted_array:
        if output[2] > 0:
            log("%s%% ~\n\t%s (%s)" %(output[2], output[0], output[1]), 'LOG')
            
def main():
    if len(argv) < 2:
        return usage()
    input_name, outputs = parse_params()
    output = check_similarity(input_name, outputs)
    if output is not None:
        collision_obj, collision_array = output
        report(collision_obj, collision_array)
    return 0

if __name__ == "__main__":
    exit(main())
