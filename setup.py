from distutils.core import setup, Extension

# Alternative method:
# https://github.com/Bitmessage/PyBitmessage/blob/master/src/pyelliptic/openssl.py

# Haven't tried that on Windows or Mac

INSTALL_REQUIRES = ['msgpack-python', 'pysha3', 'cryptography']

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
    'ipython'
]

elliptic_curve = Extension(
        'npre.elliptic_curve',
        sources=['npre/elliptic_curve/ecmodule.c'],
        include_dirs=['npre/elliptic_curve'],
        libraries=['crypto', 'gmp'])

setup(name='npre',
      version='0.3',
      description='NuCypher proxy re-encryption libraries',
      ext_modules=[elliptic_curve],
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['npre', 'npre.util'])
