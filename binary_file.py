def read(path):
    with open(path, mode="rb") as f:
        data = f.read()

    return data


def write(path, data):
    with open(path, mode="wb") as f:
        f.write(data)
