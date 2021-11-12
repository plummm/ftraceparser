import sys, os
sys.path.append(os.getcwd())

import argparse
import terminal
def parse_args():
    parser = argparse.ArgumentParser(description='Ftrace Parser')
    parser.add_argument('file', type=str, help='Ftrace file')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    t = terminal.Terminal(args.file)
    t.run()