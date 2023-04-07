from django.test import TestCase

# Create your tests here.

class Parent:

    abc = 1

class Child(Parent):
    @classmethod
    def printABC(cls):
        print(cls.abc)

Parent().printABC()