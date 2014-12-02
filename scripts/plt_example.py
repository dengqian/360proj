#!/usr/bin/python

import matplotlib.pyplot as plt

x = range(5)
y = [ _**2 for _ in x ]

plt.plot(x, y, 'r*-', label='$y=x^2$')
plt.legend(loc='lower right')
plt.title('Plot Example')
plt.xlabel('x')
plt.ylabel('y')

plt.show()
# plt.savefig('fig.pdf')
  
