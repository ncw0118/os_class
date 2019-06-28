import getopt
import os
import subprocess
import sys

##################################################################
#   file: os_classification.py
#   org: Loud Whisper Security
#   author: Noah Wallace    ncw7139@g.rit.edu
#   description: runs ping tests against a list of IP addresses
#       and classifies OS of each system based on TTL in response.
##################################################################


def options():
    # argument choices
    path = ''           # IP address input path
    output = "cmd"      # whether or not to save output to file
    ping_sweep = False  # whether or not to skip lines to use ping sweep output
    verbose = False     # additional information on output

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:o:v", ["ps"])
    except getopt.GetoptError:  # error when unhandled option presented
        sys.stderr.write("Incorrect argument usage - please use as following:\n\n"
                         "\tNo Arguments\tprompts for path to input file containing IP addresses\n\n"
                         "\t-p arg\tpath\treads from the file in the provided filepath\n\n"
                         "\t-o arg\toutput\twrites output to specified output file\n\n"
                         "\t-v\tverbose\t\tprovides TTL and result of the ping\n\n"
                         "\t--ps\tping sweep\tuses ping sweep tool output format as input\n\n")
        sys.exit()

    for o, a in opts:
        if o in ("-p", "--path"):
            path = a    # filepath path = argument
        elif o == "-o":
            output = a  # output filepath = argument
        elif o == "-v":
            verbose = True  # provide ping with OS id
        elif o == "--ps":
            ping_sweep = True   # use output of ping_sweep script
        else:
            assert False, "unhandled option"
    return path, output, verbose, ping_sweep


def os_count():
    if os.name == 'nt':        # os.name for Windows is nt
        count = '-n'           # count option for ping in Windows
    elif os.name == 'posix':   # os.name for Linux is posix
        count = '-c'           # count option for ping in Linux
    return count


def classification(path, count, output, verbose, ping_sweep):
    t = open(path)      # open path path

    if output != "cmd":
        o = open(output, 'w')
    else:
        o = open(os.devnull, 'w')

    if ping_sweep:
        for skip in range(0, 8):
            next(t)

    for line in t:      # read each line in path
        hostname = line.strip().split(' ')[0]     # removes white spaces/special characters

        if hostname.split('.')[3] == '0':
            continue

        if os.name == 'nt':
            # subprocess runs a command in the shell and pipes its output into the 'stdout' variable
            process = subprocess.Popen(['ping', count, '1', '-w', '1', hostname], stdout=subprocess.PIPE, shell=True)
            stdout = process.communicate()[0]
        elif os.name == 'posix':
            # subprocess runs a command in the shell and pipes its output into the 'stdout' variable
            process = subprocess.Popen(['ping', count, '1', '-w', '1', hostname], stdout=subprocess.PIPE)
            stdout = process.communicate()[0]

        try:    # grab ttl to determine operating system
            ttl = str(stdout).split(' ')[11][4:7]
        except:
            ttl = ''

        if ttl == '128':        # Windows default TTL = 128
            host_os = 'Windows'
        elif ttl[0:2] == '64':  # Linux default TTL = 64
            host_os = 'Linux'
        elif ttl == '254':      # Solaris/AIX default TTL = 254
            host_os = 'Solaris/AIX'
        elif ttl == '0.1' or ttl == 'ets':  # ttl value with Destination Host Unreachable for Windows/Linux
            continue
        else:
            host_os = 'uncertain'

        # build output string
        s = ""
        if verbose:
            s += "=>"
        s += "The operating system at " + hostname + " is " + host_os + "."
        if verbose:
            s += " TTL = " + ttl + "\nPing response: ----------------------------------------"
            if os.name == "posix":
                s += "\n"
            s += stdout + "-------------------------------------------------------\n"

        if output == "cmd":
            print(s)
        elif output != "cmd":
            if sys.version_info[0] < 3:
                print >>o, s
            else:
                sys.stderr.write("\nPlease run the script in Python 2.x to use the output feature.\n\n")
                break
    t.close()
    o.close()


def main():
    path, output, verbose, ping_sweep = options()
    if path == '':
        path = input('Please enter input filepath: ')
    count = os_count()
    classification(path, count, output, verbose, ping_sweep)


if __name__ == "__main__":
    main()