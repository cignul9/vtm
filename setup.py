from distutils.core import setup
setup(
  name = 'vtm',
  packages = ['vtm'],
  version = '1.4',
  description = 'Facilitates using the API to configure Brocade Virtual Traffic Managers',
  author = 'Shawn Magill',
  author_email = 'cignul9@gmail.com',
  url = 'https://github.com/cignul9',
  download_url = 'https://github.com/cignul9/vtm/tarball/1.4',
  install_requires = [
    'requests',
  ],
  keywords = ['vtm', 'SteelApp', 'Stingray', 'load balancer'],
)
