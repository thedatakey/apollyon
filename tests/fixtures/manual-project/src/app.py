import pickle


def calculate(expression):
    return eval(expression)


def restore(payload):
    return pickle.loads(payload)
