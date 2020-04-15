import argparse

def parseArgs():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', help='file containing list of ecs task definitions', required=True)
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parseArgs()
    family = {}
    with open(args.f, 'r') as fd:
        for line in fd:
            l = line.strip()
            family_name = l[:l.rfind(':')]
            version_int = int(l[l.rfind(':') + 1:])
            if family_name not in family:
                family[family_name] = version_int
            if family[family_name] < version_int:
                family[family_name] = version_int
    for family, version in family.items():
        print('{}:{}'.format(family, version))
