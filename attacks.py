import whereParser
import rowFiller
import pprint
import re
import requests
import pandas as pd
import numpy as np

defaultNumSamples = 100               # number of times each test should repeat (for average)

class runAttack:
    ''' Contains various support routines for running attacks '''
    def __init__(self,attack,queryUrl='https://db-proto.probsteide.com/api',
                 fileUrl='https://db-proto.probsteide.com/api/upload-db'):
        self.pp = pprint.PrettyPrinter(indent=4)
        self.attack = attack
        self.queryUrl = queryUrl
        self.fileUrl = fileUrl
        dop = False
        if 'doprint' in self.attack:
            dop = self.attack['doprint']
        # build attack database
        self.sw = whereParser.simpleWhere(attack['conditionsSql'])
        self.rf = rowFiller.rowFiller(self.sw,printIntermediateTables=False,dop=dop)
        self.rf.makeBaseTables()
        if len(self.rf.failedCombinations) > 0:
            print("Failed Combinations:")
            print(self.rf.failedCombinations)
        for change in attack['changes']:
            if change['change'] == 'append':
                self.rf.appendDf(change['table'],change['spec'])
            elif change['change'] == 'strip':
                self.rf.stripDf(change['table'],change['query'])
        self.rf.baseTablesToDb()
        self.postDb()

    def runCheck(self):
        self.runAttack(check=True)

    def runAttack(self,check=False):
        ''' This just checks to make sure that an attack on the raw data works as expected '''
        attackFunc = self.attackMap[self.attack['attackType']]
        if attackFunc(self,check=check):
            print(f"PASSED: {self.attack['describe']}")

    def queryAnon(self,sql,anon=True,db='testAttack.db'):
        aidCols = self.rf.getAidColumns()
        req = {'Anonymize':anon,
               'database':db,
               'query':sql,
               'seed':1,
               'aid_columns':aidCols,
               }
        response = requests.post(self.queryUrl, json=req)
        ans = response.json()
        if ans['success'] == False:
            print("Query Error")
            self.pp.pprint(ans)
            return None
        return ans

    def postDb(self):
        fin = open(self.rf.getDbPath(), 'rb')
        data = fin.read()
        files = {'file': fin}
        headers = {
            'db-name':self.rf.getDbName(),
            'password':'great success',
            'Content-Type': 'application/octet-stream',
        }
        r = requests.post(url=self.fileUrl, data=data, headers=headers)
        print(r.text)
        fin.close()

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
        if ans1 <= 5 or ans2 <= 5 or diff != self.attack['difference']:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            ans1 {ans1}, ans2 {ans2}, expected {self.attack['difference']}, got {diff}''')
        return True

    def _test(self, check=False):
        ''' does nothing '''
        print("Just a test:")
        if self.attack['doprint']:
            self.pp.pprint(self.attack)
        return True

    def _doSqlReplace(self,sql):
        cols = re.findall('-..-',sql)
        for col in cols:
            val = self.rf.getNewRowColumn(col[1:3])
            pattern = f"-{col[1:3]}-"
            sql = re.sub(pattern,str(val),sql)
        return sql

    def _sortAnsByBucket(self,ans):
        s = {}
        for row in ans:
            s[row[0]] = row[1]
        return s

    def _simpleFirstDerivitiveDifference(self, check=False):
        if check:
            # First run check to make sure that the attack works on raw data
            sql1 = self._doSqlReplace(self.attack['attack1'])
            ans1 = self.rf.queryDb(sql1)
            sql2 = self._doSqlReplace(self.attack['attack2'])
            ans2 = self.rf.queryDb(sql2)
        else:
            pass
        sort1 = self._sortAnsByBucket(ans1)
        sort2 = self._sortAnsByBucket(ans2)
        maxDiff = float('-inf')
        maxBucket = None
        for bucket,count1 in sort1.items():
            if bucket in sort2:
                count2 = sort2[bucket]
                diff = count2 - count1
                if diff > maxDiff:
                    maxBucket = bucket
                    maxDiff = diff
        if maxBucket != self.attack['victimBucket']:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            ans1 {ans1}, ans2 {ans2}, expected {self.attack['victimBucket']}, got {maxBucket}''')
        return True

    def _simpleListUsers(self, check=False):
        if check:
            # First run check to make sure that the attack works on raw data
            sql1 = self._doSqlReplace(self.attack['attack'])
            ans1 = self.rf.queryDb(sql1)
        else:
            pass
        # TODO: deal with error or null responses from queryDb
        if len(ans1) < 1:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            got len {len(ans1)}''')
        return True

    def _simpleAveraging(self, check=False):
        # This query is on the raw data, so that we learn the expected exact answer
        sql1 = self._doSqlReplace(self.attack['attack'])
        exactCount = self.rf.queryDb(sql1)[0][0]
        if check:
            sumCounts = 0
            for _ in range(self.attack['repeats']):
                sumCounts += self.rf.queryDb(sql1)[0][0]
            averagedCount = sumCounts / self.attack['repeats']
            if averagedCount != exactCount:
                self._error(f'''ERROR: {self.attack['attackType']}: failed check
                                got averaged count {averagedCount}, expected {exactCount}''')
            return True
        pass
        ans = self.queryAnon(sql1)
        if ans is not None:
            self.pp.pprint(ans)
        return True

    def _splitAveraging(self, check=False):
        # This query is on the raw data, so that we learn the expected exact answer
        sql = self._doSqlReplace(self.attack['checkQuery'])
        exactCount = self.rf.queryDb(sql)[0][0]
        if check:
            sumCounts = 0
            for val in self.attack['attackVals']:
                sql1 = self.attack['attackTemplate1'].replace('---',str(val))
                sumCounts += self.rf.queryDb(sql1)[0][0]
                sql2 = self.attack['attackTemplate2'].replace('---',str(val))
                sumCounts += self.rf.queryDb(sql2)[0][0]
            averagedCount = sumCounts / len(self.attack['attackVals'])
        else:
            pass
        if averagedCount != exactCount:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            got averaged count {averagedCount}, expected {exactCount}''')
        return True

    attackMap = {
        'simpleDifference': _simpleDifference,
        'simpleFirstDerivitiveDifference': _simpleFirstDerivitiveDifference,
        'simpleListUsers': _simpleListUsers,
        'simpleAveraging': _simpleAveraging,
        'splitAveraging': _splitAveraging,
        'test': _test,
    }

if True: testControl = 'firstOnly'    # executes only the first test
elif False: testControl = 'tagged'    # executes only tests so tagged
else: testControl = 'all'             # executes all tests

''' List of Attacks '''
attacks = [
    {   
        'tagAsRun': False,
        'attackType': 'simpleAveraging',
        'describe': 'Simple averaging attack to learn exact count',
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100",
        'changes': [
        ],
        'attack': "select count(distinct aid1) from tab where t1='y'",
        'repeats': 100,
    },
    {   
        'tagAsRun': False,
        'attackType': 'splitAveraging',
        'describe': 'Split averaging attack to learn exact count',
        'conditionsSql': '''select count(*) from tab where t1='y' or
                            i1 in (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20)''',
        'changes': [
        ],
        'checkQuery': "select count(distinct aid1) from tab where t1='y'",
        'attackTemplate1': "select count(distinct aid1) from tab where t1='y' and i1 = ---",
        'attackTemplate2': "select count(distinct aid1) from tab where t1='y' and i1 <> ---",
        'attackVals': [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20],
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleListUsers',
        'describe': 'Select star',
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100",
        'changes': [
        ],
        'attack': "select * from tab",
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleFirstDerivitiveDifference',
        'describe': '''First derivitive difference attack with NAND'd AND group,
                       victim does not have attribute''',
        # We want to learn which t1 bucket the victim is in
        'conditionsSql': '''select count(*) from tab where t1 in ('a','b','c') or
                            i1 = 100 or t2 = 'x' or t3 = 'y' ''',
        # I want to make a scenario where the victim does not have t1=y.
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'x' and i1 == 100 and t3 == 'y'"},
            {'change':'append', 'table':'tab','spec': {'t1':['a'],'t2':['x'],'i1':[100],'t3':['y']}},
        ],
        # The first query definately has the user
        'attack1': '''select t1, count(distinct aid1) from tab where
                             not (i1 = 100 and t2 = 'x' and t3 = 'y') group by 1''',
        'attack2': "select t1, count(distinct aid1) from tab group by 1",
        'victimBucket': 'a',
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleFirstDerivitiveDifference',
        'describe': 'First derivitive difference attack with single NAND, victim does not have attribute',
        # We want to learn which t1 bucket the victim is in
        'conditionsSql': "select count(*) from tab where t1 in ('a','b','c') and i1 = 100",
        # I want to make a scenario where the victim does not have t1=y.
        'changes': [
            {'change':'append', 'table':'tab','spec': {'t1':['a'],'i1':['unique']}},
        ],
        # The first query definately has the user
        'attack1': "select t1, count(distinct aid1) from tab where i1 <> -i1- group by 1",
        'attack2': "select t1, count(distinct aid1) from tab group by 1",
        'victimBucket': 'a',
    },
    {   
        'doprint': False,
        'tagAsRun': False,
        'attackType': 'test',
        'describe': 'Just testing a new conditionsSql',
        # The attack here is where there is one user with t2 = 'f'. Want to learn t1
        'conditionsSql': "select count(*) from tab where t1='y' and t2 in ('a','b','c')",
        # Remove all t2='f' then add one back in
        'changes': [
            #{'change':'strip', 'table':'tab','query': "t2 == 'f'"},
            #{'change':'append', 'table':'tab','spec': {'t1':['unique'],'t2':['f']}},
        ],
        # The first query definately excludes the victim
        'attack1': "select count(distinct aid1) from tab where t1='y' and t2 = 'zz'",
        # The second query may or may not (in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1='y'",
        'difference': 0
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with lone woman, victim does not have attribute',
        # The attack here is where there is one user with t2 = 'f'. Want to learn t1
        'conditionsSql': "select count(*) from tab where t1='y' or t2 in ('f','m')",
        # Remove all t2='f' then add one back in
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'f'"},
            {'change':'strip', 'table':'tab','query': "t2 == 'zz'"},
            {'change':'append', 'table':'tab','spec': {'t1':['unique'],'t2':['f']}},
        ],
        # The first query definately excludes the victim
        'attack1': "select count(distinct aid1) from tab where t1='y' and t2 = 'm'",
        # The second query may or may not (in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1='y'",
        'difference': 0
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': "Simple difference attack with NAND'd AND group, victim does not have attribute",
        # The attack here is where there is one user with a unique combination of i1 and t2
        # values, though each individually is not unique
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100 or t2='x'",
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'x' and i1 == 100"},
            {'change':'append', 'table':'tab','spec': {'t1':['unique'],'i1':[100],'t2':['x']}},
        ],
        # The first query definately excludes the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' and not (i1 = 100 and t2 = 'x')",
        # The second query may or may not (but in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is 0
        'difference': 0
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': "Simple difference attack with NAND'd AND group, victim has attribute",
        # The attack here is where there is one user with a unique combination of i1 and t2
        # values, though each individually is not unique
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100 or t2='x'",
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'x' and i1 == 100"},
            {'change':'append', 'table':'tab','spec': {'t1':['y'],'i1':[100],'t2':['x']}},
        ],
        # The first query definately excludes the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' and not (i1 = 100 and t2 = 'x')",
        # The second query may or may not (but in this case also does).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is 0
        'difference': -1
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single NAND, victim has attribute',
        # The attack here is where there is one user with a unique value in column i1
        # We want to know if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100",
        # I want to make a scenario where the victim has t1=y. So I add a row with unique
        # i1 and t1='y'
        'changes': [
            {'change':'append', 'table':'tab','spec': {'aid1':['unique'],'t1':['y'],'i1':['unique']}},
        ],
        # The first query definately excludes the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' and i1 <> -i1-",
        # The second query may or may not (but in this case also does).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is -1
        'difference': -1
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single NAND, victim does not have attribute',
        # The attack here is where there is one user with a unique i1. We want to know
        # if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100",
        # I want to make a scenario where the victim does not have t1=y.
        'changes': [
            {'change':'append', 'table':'tab','spec': {'t1':['unique'],'i1':['unique']}},
        ],
        # The first query definately excludes the user
        'attack1': "select count(distinct aid1) from tab where t1='y' and i1 <> -i1-",
        # The second query may or may not (in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1='y'",
        # If the second query does not have the victim, then the difference is 1
        'difference': 0
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': "Simple difference attack with OR'd AND group, victim does not have attribute",
        # The attack here is where there is one user with a unique combination of i1 and t2
        # values, though each individually is not unique
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100 or t2='x'",
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'x' and i1 == 100"},
            {'change':'append', 'table':'tab','spec': {'t1':['unique'],'i1':[100],'t2':['x']}},
        ],
        # The first query definately has the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' or (i1 = 100 and t2 = 'x')",
        # The second query may or may not (but in this case does not).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is 0
        'difference': 1
    },
    {   
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': "Simple difference attack with OR'd AND group, victim has attribute",
        # The attack here is where there is one user with a unique combination of i1 and t2
        # values, though each individually is not unique
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100 or t2='x'",
        'changes': [
            {'change':'strip', 'table':'tab','query': "t2 == 'x' and i1 == 100"},
            {'change':'append', 'table':'tab','spec': {'t1':['y'],'i1':[100],'t2':['x']}},
        ],
        # The first query definately has the victim
        'attack1': "select count(distinct aid1) from tab where t1 = 'y' or (i1 = 100 and t2 = 'x')",
        # The second query may or may not (but in this case also does).
        'attack2': "select count(distinct aid1) from tab where t1 = 'y'",
        # If the second query has the victim, then the difference is 0
        'difference': 0
    },
    {   
        'tagAsRun': False,
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
        'tagAsRun': False,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single OR, victim does not have attribute',
        # The attack here is where there is one user with a unique i1. We want to know
        # if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=100",
        # I want to make a scenario where the victim does not have t1=y.
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

for attack in attacks:
    if (testControl == 'firstOnly' or testControl == 'all' or
        (testControl == 'tagged' and attack['tagAsRun'])):
        ra = runAttack(attack)
        ra.runCheck()
        ra.runAttack()
    if testControl == 'firstOnly':
        break
