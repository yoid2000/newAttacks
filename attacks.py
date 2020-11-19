import whereParser
import rowFiller
import pprint

''' Configuration '''
if True: testControl = 'firstOnly'    # executes only the first test
elif False: testControl = 'tagged'    # executes only tests so tagged
else: testControl = 'all'             # executes all tests

defaultNumSamples = 100               # number of times each test should repeat (for average)

class runAttack:
    ''' Contains various support routines for running attacks '''
    def __init__(self,attack):
        self.pp = pprint.PrettyPrinter(indent=4)
        self.attack = attack
        # build attack database
        self.sw = whereParser.simpleWhere(attack['conditionsSql'])
        self.rf = rowFiller.rowFiller(self.sw)
        self.rf.makeBaseTables()
        if len(self.rf.failedCombinations) > 0:
            print("Failed Combinations:")
            print(self.rf.failedCombinations)
            quit()
        self.rf.pruneBaseTables(attack['prune']['table'],attack['prune']['query'])

    def runAttack(self):
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
            ans1 = self.rf.queryDb(self.attack['attack1'])[0][0]
            ans2 = self.rf.queryDb(self.attack['attack2'])[0][0]
        else:
            pass
        diff = ans1 - ans2
        if diff != self.attack['difference']:
            self._error(f'''ERROR: {self.attack['attackType']}: failed check
                            ans1 {ans1}, ans2 {ans2}, expected {self.attack['difference']}, got {diff}''')
        return True

    attackMap = {
        'simpleDifference': _simpleDifference,
    }


''' List of Attacks '''
attacks = [
    {   
        'tagAsRun': True,
        'attackType': 'simpleDifference',
        'describe': 'Simple difference attack with single OR',
        # The attack here is where there is one user with i1=12345. We want to know
        # if that user has value t1='y' or not.
        'conditionsSql': "select count(*) from tab where t1='y' or i1=12345",
        # I want to make a scenario where the victim does not have t1=y. So I prune all
        # but one of the users that has i1=12345 but not t1=y
        'prune': {'table':'tab','query': "t1 != 'y' and i1 == 12345"},
        # The first query definately has the user
        'attack1': "select count(distinct aid1) from tab where t1='y' or i1=12345",
        # The second query may or may not.
        'attack2': "select count(distinct aid1) from tab where t1='y'",
        # If the second query does not have the victim, then the difference is 1
        'difference': 1
    },
]

if True: testControl = 'firstOnly'    # executes only the first test
elif False: testControl = 'tagged'    # executes only tests so tagged
else: testControl = 'all'             # executes all tests
for attack in attacks:
    if (testControl == 'firstOnly' or testControl == 'all' or
        (testControl == 'tagged' and attack['tagAsRun'])):
        ra = runAttack(attack)
        ra.runAttack()
    if testControl == 'firstOnly':
        break
