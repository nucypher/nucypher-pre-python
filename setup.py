from distutils.core import setup, Extension

# Alternative method:
# https://github.com/Bitmessage/PyBitmessage/blob/master/src/pyelliptic/openssl.py

# Haven't tried that on Windows or Mac

elliptic_curve = Extension(
        'npre.elliptic_curve',
        sources=['npre/elliptic_curve/ecmodule.c', 'npre/util/base64.c'],
        include_dirs=['npre/util'],
        libraries=['crypto', 'gmp'])

setup(name='npre',
      version='0.1',
      description='NuCypher proxy re-encryption libraries',
      ext_modules=[elliptic_curve],
      packages=['npre'])
