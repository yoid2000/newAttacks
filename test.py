import itertools

boo = [['1','c'],'2',['3','d']]
hoo = [['x','y'],'w']
for x in itertools.product(boo):
    print(x)
for x in itertools.product(*boo):
    print(x)
for x in itertools.product(*boo,*hoo):
    print(x)
