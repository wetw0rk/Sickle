import setuptools

setuptools.setup(
  name='sickle',
  version="3.1.0",
  author="Milton Valencia (wetw0rk)",
  description="Payload development framework",
  url="https://github.com/wetw0rk/Sickle",
  packages=setuptools.find_packages(exclude=['documentation']),
  entry_points={
    'console_scripts': [
      'sickle = sickle.__main__:entry'
    ]
  },

  classifiers=[
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.11",
    "License :: OSI Approved :: MIT license",
    "Operating System :: OS Independent",
  ],
)
