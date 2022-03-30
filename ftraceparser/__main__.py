import sys, os
sys.path.append(os.getcwd())

import argparse
import terminal
import trace_cmd
from ftraceparser import trace

def parse_args():
    parser = argparse.ArgumentParser(description='Ftrace Parser')
    parser.add_argument('file', nargs='?', type=str, help='Ftrace file')
    parser.add_argument('-i', nargs='?', type=str, help='Process to run')
    parser.add_argument('-c', nargs='?', type=str, help='Convert ftrace file to trace-cmd style')
    parser.add_argument('-g', action='append', default=[], help='Specify entry functions')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    if args.i != None:
        tc = trace_cmd.TraceCmd(args.i)
        cmd = tc.get_record_cmd()
        if cmd != None:
            print(cmd)
        exit(0)
    
    if args.c != None:
        t = trace.Trace()
        t.convert_ftrace(args.c, args.g)
        exit(0)
    
    t = terminal.Terminal(args.file)
    t.run()