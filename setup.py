from setuptools import setup, find_packages
import re

VERSIONFILE="amurex/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	name="amurex",
	version=verstr,
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	packages=find_packages(),
	include_package_data=True,
	url="https://github.com/skelsec/amurex",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="",
	long_description="",
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"Operating System :: OS Independent",
	),
	install_requires=[
        'cryptography>=2.5',
		'unicrypto>=0.0.9',
		'asysocks>=0.2.0',
		'asyauth>=0.0.1',
		'prompt-toolkit>=3.0.20',
	],
	#entry_points={
	#	'console_scripts': [
	#		'octopwn = octopwn.octopwn:main',
	#		'octopwnserver = octopwn.remote.server.__main__:main',
	#		'octopwnclient = octopwn.remote.client.__main__:main',
	#	],
	#}
)