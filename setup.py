from distutils.core import setup, Extension

# Alternative method:
# https://github.com/Bitmessage/PyBitmessage/blob/master/src/pyelliptic/openssl.py

# Haven't tried that on Windows or Mac

INSTALL_REQUIRES = ['msgpack-python']

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
]

elliptic_curve = Extension(
        'npre.elliptic_curve',
        sources=['npre/elliptic_curve/ecmodule.c', 'npre/util/base64/base64.c'],
        include_dirs=['npre/base64/util', 'npre/elliptic_curve'],
        libraries=['crypto', 'gmp'])

setup(name='npre',
      version='0.1',
      description='NuCypher proxy re-encryption libraries',
      ext_modules=[elliptic_curve],
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['npre', 'npre.util'])
