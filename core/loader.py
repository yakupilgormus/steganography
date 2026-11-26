import importlib, pkgutil

def load_cogs(package="cogs"):
    pkg = importlib.import_module(package)
    loaded = []
    for _, name, _ in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"{package}.{name}")
        loaded.append(module)
    return loaded
