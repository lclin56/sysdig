from setuptools import setup, find_packages

setup(
    name='pyfbeng',
    version='1.0.240301',
    packages=find_packages(),
    description='Falcon Behavior Engine: A software suspicious behavior detection engine.',
    long_description='Falcon Behavior Engine (fbeng) is designed to detect and analyze suspicious behaviors in software, providing a powerful tool for security monitoring and analysis.',
    author='li.cl',
    author_email='li.cl@asiainfo-sec.com',
    url='',
    install_requires=[
        # Dependencies here
    ],
    package_data={
        'pyfbeng': ['fbeng.py', 'libfbeng.so'],
    },
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4',
)
