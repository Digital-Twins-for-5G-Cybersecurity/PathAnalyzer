import r2pipe       # for radare api calls 
import argparse     # for argument parsing
import rich         # for cleaner terminal output
import sys
import os

# Global variables that dictate the flags used
VERBOSE_FLAG = False
VERY_VERBOSE_FLAG = False
OUTPUT_TEXT_FLAG = None
OUTPUT_JSON_FLAG = None
r2 = None

def establish_breakpoints():
    """ Gets all of the functions and labels in the executable and sets a breakpoint at all of them 

    Args:
        r2 (r2 object): the object returned by opening an r2pipe
    """
    
    global r2
    
    r2.cmd("db main")
    r2.cmd("dc")
    
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Retrieving all forward edges...") 
    # retrieve every call instruction in the executable as a json object    
    allCalls = r2.cmd("/ao call")
    
    # print all call instructions if verbosity flag is met
    if (VERY_VERBOSE_FLAG):
        print(allCalls)
        
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Retrieving all backward edges...") 
    
    # retrieve every call instruction in the executable as a json object    
    allRets = r2.cmd("/ao ret")
    
    # print all ret instructions if verbosity flag is met
    if (VERY_VERBOSE_FLAG):
        print(allRets)
    
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Setting all breakpoints...") 
        
    # set a breakpoint at every call instruction
    allCalls = allCalls.split('\n')[:-1]
    for line in allCalls:
        line = line.split(" ")
        line = [x for x in line if x != ""]
        
        r2.cmd("db " + line[0])
        
    # set a breakpoint at every ret instruction
    allRets = allRets.split('\n')[:-1]
    for line in allRets:
        line = line.split(" ")
        line = [x for x in line if x != ""]
        r2.cmd("db " + line[0])


def init_analysis(executable, arguments):
    """Initializes radare2 analysis 

    Args:
        executable (string): the name of the executable file
        arguments (string): the arguments to be passed to the executable file
        
    Returns:
        r2 object
    """
    global r2
    
    # strip single quotes from strings and format for r2pipe
    executable = executable[1:-1]
    arguments = arguments[1:-1]
    arguments = arguments.split(" ")

    
    # initialize r2pipe
    if (VERY_VERBOSE_FLAG):
        r2 = r2pipe.open(executable)
    else: 
        r2 = r2pipe.open(executable, flags=['-2'])
    
    # analyze executable file and print in terminal based on verbosity 
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Analyzing executable file. This can take some time...")
    r2.cmd("doo")
    r2.cmd("aaa")
    if (VERY_VERBOSE_FLAG):
        print()
    r2.cmd("ds")
    
def execute_program():
    """ Runs the program logging all forward and backward branches
    """
    global r2
    
    # Running file and logging fucntion calls
    r2.cmd("dc")
    outFrom = r2.cmdj("afij")
    r2.cmd("ds")
    outTo = r2.cmdj("afij")
    print("CALL --", outFrom[0]["name"], "->", outTo[0]["name"] )
    
    r2.cmd("dc")
    outFrom = r2.cmdj("afij")
    r2.cmd("ds")
    outTo = r2.cmdj("afij")
    print("UNDEFINED --", outFrom[0]["name"], "->", outTo[0]["name"] )
    
        
        


def main(argv):
    """Main functionality of the program
    Args:
        argv (list of strings): the arguments to be passed into the program
    """
    # gather global vars 
    global VERBOSE_FLAG
    global VERY_VERBOSE_FLAG
    global OUTPUT_TEXT_FLAG
    global OUTPUT_JSON_FLAG
    
    # initializing argparser and defining all of the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increases the verbosity of the program", action="store_true")
    parser.add_argument("-vv", "--very-verbose", help="verbosity information is split into multiple window", action="store_true")
    parser.add_argument("-ot", "--output-text", help="stores the output of the program into a text file", type=ascii)
    parser.add_argument("-oj", "--output-json", help="stores the output of the program into a json file", type=ascii)
    parser.add_argument("executable", help="executable file to be analyzed", type=ascii)
    parser.add_argument("-args", "--arguments", help="arguments to be passed to the executable. must be passed with double quotes", type=ascii, default="")
    args = parser.parse_args()
    
    # defining global variables based on arguments
    if args.verbose:
        VERBOSE_FLAG = True
    elif args.very_verbose:
        VERY_VERBOSE_FLAG = True
    if args.output_text != None:
        OUTPUT_TEXT_FLAG = args.output_text
    if args.output_json != None:
        OUTPUT_JSON_FLAG = args.output_json
        
    
    # Analyze given file with radare2
    init_analysis(str(args.executable), str(args.arguments))
    establish_breakpoints()
    execute_program()
    return 0
    
    

if __name__ == "__main__":
    """Run this if the program is run from the command line"""
    main(sys.argv)