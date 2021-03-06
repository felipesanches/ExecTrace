import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="exectrace-pkg-FelipeSanches", # Replace with your own username
    version="0.0.1",
    author="Felipe Corrêa da Silva Sanches",
    author_email="juca@members.fsf.org",
    description="Offers a CPU-agnostic mechanism for analysing binaries by mapping all possible code-paths.",
    long_description="Offers a CPU-agnostic mechanism for analysing binaries by mapping all possible code-paths. In order to use it, one needs to provide a child-class that inherits from the abtract ExecTrace class.",
    long_description_content_type="text/markdown",
    url="https://github.com/felipesanches/ExecTrace",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)