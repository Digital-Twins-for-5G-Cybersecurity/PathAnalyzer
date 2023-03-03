import r2pipe       # for radare api calls 
import argparse     # for argument parsing
import threading    # for multithreading output handler
import rich         # for cleaner terminal output
from output_handler import OutputHandler
import sys
import os

# Global variables that dictate the flags used
VERBOSE_FLAG = False
VERY_VERBOSE_FLAG = False
OUTPUT_TEXT_FLAG = None
OUTPUT_JSON_FLAG = None
r2 = None

# Shared variables for multithreading
OUTPUT_DATA = []
OUTPUT_FINISHED = False



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

    
    # initialize r2pipe
    if (VERY_VERBOSE_FLAG):
        r2 = r2pipe.open(executable)
    else: 
        r2 = r2pipe.open(executable, flags=['-2'])
    
    # analyze executable file and print in terminal based on verbosity 
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Analyzing executable file. This can take some time...")
    r2.cmd("ood " + arguments)
    r2.cmd("aaa")
    if (VERY_VERBOSE_FLAG):
        print()
    r2.cmd("db main")
    r2.cmd("dc")
    
def establish_breakpoints():
    """ Gets all of the functions and labels in the executable and sets a breakpoint at all of them 

    Args:
        r2 (r2 object): the object returned by opening an r2pipe
    """
    
    global r2
    
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Retrieving all function addresses...") 
    # retrieve every function address in the executable as a json object    
    allFunctions = r2.cmdj("aflj")
    all_func_names = []
    
    # print all functions  if verbosity flag is met
    if (VERY_VERBOSE_FLAG):
        print(r2.cmd("afl"))
    
    
    if (VERBOSE_FLAG or VERY_VERBOSE_FLAG):
        print("Setting forward edge breakpoints...") 
        
    # Establish breakpoints at all functions
    for func in allFunctions:
        r2.cmd("db " + func["name"]) 
        all_func_names.append(func["name"])
        
        #Establish breakpoints at all function call XREFs
        if "codexrefs" in func:
            for call in func["codexrefs"]:
                r2.cmd("db " + str(call["addr"]))
    
    # Establish breakpoints at all jmp xrefs
    jmp_instrs = r2.cmd("/ao jmp").split('\n')
    for line in jmp_instrs:
        line = line.split(" ")
        line = [x for x in line if x]
        if len(line) != 0 and line[-1] in all_func_names:
            r2.cmd("db " + line[0])
          
def handle_output(filename, file_type):
    """ Handles the file outputs and types as a thread

    Args:
        filename (String): The name of the file 
        file_type (String): The type of the fie
    """
    global OUTPUT_DATA
    global OUTPUT_FINISHED
    
    handler = OutputHandler(filename, file_type)
    current_index = 0;
    while not OUTPUT_FINISHED or len(OUTPUT_DATA) > current_index:
        if len(OUTPUT_DATA) > current_index:
            handler.appendJSON(OUTPUT_DATA[current_index])
            current_index += 1;
    
    handler.closeFile()
        
def execute_program():
    """ Runs the program logging all forward and backward branches
    """
    global OUTPUT_FINISHED
    global r2
    
    # Define shadow call Stack and return address dictionary
    call_stack = []
    ret_addresses = {}
    
    if VERBOSE_FLAG or VERY_VERBOSE_FLAG:
        print("Executing Program...")
        
    while True:
        r2.cmd("dc")
        # Is address at breakpoint in return dictionary
        current_address = int(r2.cmd("dr? rip"), 16)        # get the current address
        if current_address in ret_addresses:                # This means it is a return address
            corr_function = ret_addresses.pop(current_address)
            function_pop = call_stack.pop()
            while (function_pop != corr_function and len(call_stack) > 0):          # Pop Stack until coorelating function name is reached
                second_function = call_stack.pop()

                OUTPUT_DATA.append({"instr":"RET", "from": function_pop, "to": second_function}) 
                
                if VERY_VERBOSE_FLAG:
                    print("RET  --", second_function, "<--", function_pop)
                function_pop = second_function
                
            # Get current function name
            to_func = r2.cmdj("afij")
            if len(to_func) == 0:
                to_func = "UNKNOWN"
            else:
                to_func = to_func[0]["name"]
                
            OUTPUT_DATA.append({"instr":"RET", "from": function_pop, "to": to_func})
            
            if VERY_VERBOSE_FLAG:
                print("RET  --", to_func, "<--", function_pop)
        
        else:                                               # Function gets called 
            current_address_info = r2.cmdj("aoj @ rip")
            if len(current_address_info) == 0:
                break
            opcode_size = current_address_info[0]["size"]
            from_func = r2.cmdj("afij")
            if len(from_func) == 0:
                from_func = "UNKNOWN"
            else:
                from_func = from_func[0]["name"] 
                
            ret_address = current_address + opcode_size
            r2.cmd("db " + str(ret_address))                # set breakpoint at the return address 
            r2.cmd("dc")
            to_func = r2.cmdj("afij")
            if len(to_func) == 0:
                to_func = "UNKNOWN"
            else:
                to_func = to_func[0]["name"]
                
            call_stack.append(to_func)
            ret_addresses[ret_address] = to_func
            
            OUTPUT_DATA.append({"instr":"CALL", "from": from_func, "to": to_func}) 
            
            if VERY_VERBOSE_FLAG:
                print("CALL --", from_func, "-->", to_func)
    
    program_exit_status = int(r2.cmd("dr rdi"), 16)
    
    OUTPUT_DATA.append({"exit_status": str(program_exit_status)})
    
    if VERBOSE_FLAG or VERY_VERBOSE_FLAG:
        print("Program exited with status:", program_exit_status)
        
    OUTPUT_FINISHED = True
    
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
        
        
    if OUTPUT_JSON_FLAG:
        filename = args.output_json[1:-1]
        handle_json_output = threading.Thread(target = handle_output, args=(filename, ".json",))
        handle_json_output.start()
    
    # Analyze given file with radare2
    init_analysis(str(args.executable), str(args.arguments))
    establish_breakpoints()
    program_execution = threading.Thread(target=execute_program)
    program_execution.start()
    
    program_execution.join()
    
    if OUTPUT_JSON_FLAG:
        handle_json_output.join()
    
    return 0
    
    

if __name__ == "__main__":
    """Run this if the program is run from the command line"""
    main(sys.argv)