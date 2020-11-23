import whereParser
import rowFiller
import pprint
import re
import pandas as pd
import numpy as np

defaultNumSamples = 100               # number of times each test should repeat (for average)

class runAttack:
    ''' Contains various support routines for running attacks '''
    def __init__(self,attack):
        self.pp = pprint.PrettyPrinter(indent=4)
        self.attack = attack
        # build attack database
        self.sw = whereParser.simpleWhere(attack['conditionsSql'])
        self.rf = rowFiller.rowFiller(self.sw,printIntermediateTables=False)
        self.rf.makeBaseTables()
        if len(self.rf.failedCombinations) > 0:
            print("Failed Combinations:")
            print(self.rf.failedCombinations)
            quit()
        for change in attack['changes']:
            if change['change'] == 'append':
                self.rf.appendDf(change['table'],change['spec'])
            elif change['change'] == 'strip':
                self.rf.stripDf(change['table'],change['query'])
        self.rf.baseTablesToDb()

    def runCheck(self):
        ''' This just checks to make sure that an attack on the raw data works as expected '''
        attackFunc = self.attackMap[self.attack['attackType']]
        if attackFunc(self,check=True):
            print(f"PASSED: {self.attack['describe']}")

    def _error(self,msg):
        print(msg)
        self.pp.pprint(self.attack)
        quit()

    def _simpleDifference(self,check=False):
        if check:
            # First run check to make sure that the attack works on raw data
            sql1 = self._doSqlReplace(self.attack['attack1'])
            ans1 = self.rf.queryDb(sql1)[0][0]
            sql2 = self._doSqlReplace(self.attack['attack2'])
            ans2 = self.rf.queryDb(sql2)[0][0]
        else:
            pass
        diff = ans1 - ans2
        if diff != self.attack['difference']:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            ans1 {ans1}, ans2 {ans2}, expected {self.attack['difference']}, got {diff}''')
        return True

    def _doSqlReplace(self,sql):
        cols = re.findall('-..-',sql)
        for col in cols:
            val = self.rf.getNewRowColumn(col[1:3])
            pattern = f"-{col[1:3]}-"
            sql = re.sub(pattern,str(val),sql)
        return sql

    attackMap = {
        'simpleDifference': _simpleDifference,
    }

''' List of Attacks '''
attacks = [
    {   
        'tagAsRun': True,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single OR, victim has attribute',
        # The attack here is where there is one user with a unique value in column i1
        # We want to know if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=3456",
        # I want to make a scenario where the victim has t1=y. So I add a row with unique
        # i1 and t1='y'
        'changes': [
            {'change':'append', 'table':'tab','spec': {'aid1':['unique'],'t1':['y'],'i1':['unique']}},
        ],
        # The first query definately has the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' or i1 = -i1-",
        # The second query may or may not (but in this case also does).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is 0
        'difference': 0
    },
    {   
        'tagAsRun': True,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single OR, victim does not have attribute',
        # The attack here is where there is one user with i1=12345. We want to know
        # if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=12345",
        # I want to make a scenario where the victim does not have t1=y. So I prune all
        # but one of the users that has i1=12345 but not t1=y
        'changes': [
            {'change':'append', 'table':'tab','spec': {'t1':['unique'],'i1':['unique']}},
        ],
        # The first query definately has the user
        'attack1': "select count(distinct aid1) from tab where t1='y' or i1 = -i1-",
        # The second query may or may not (in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1='y'",
        # If the second query does not have the victim, then the difference is 1
        'difference': 1
    },
]

if False: testControl = 'firstOnly'    # executes only the first test
elif True: testControl = 'tagged'    # executes only tests so tagged
else: testControl = 'all'             # executes all tests

for attack in attacks:
    if (testControl == 'firstOnly' or testControl == 'all' or
        (testControl == 'tagged' and attack['tagAsRun'])):
        ra = runAttack(attack)
        ra.runCheck()
    if testControl == 'firstOnly':
        break
