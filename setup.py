from distutils.core import setup
setup(
  name = 'vtm',
  packages = ['vtm'],
  version = '0.2',
  description = 'A library to facilitate using the API to configure Brocade Virtual Traffic Managers',
  author = 'Shawn Magill',
  author_email = 'cignul9@gmail.com',
  url = 'https://github.com/cignul9',
  download_url = 'https://github.com/cignul9/vtm/tarball/0.2',
  install_requires=[
    'requests',
    'json',
    'sys',
    'warnings',
    'pprint',
    're',
  ],
  keywords = [
    'stingray',
    'vtm',
    'brocade',
    'traffic manager',
    'api'
  ],
  classifiers = [],
)