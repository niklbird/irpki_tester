# iRPKI Test
To run the test
- Compile Routinator with the included rpki-rs library.
- Then create a repository by running the main of cure_pp. 
- Install nginx and point it to the folder where the repository was created. By default, that is cure_pp/data/
- Run Routinator with flag --irpki to use the iRPKI Notification file. Without the flag, it will run default Routinator. 

The tooling is experimental and part of active research. As such, it might include bugs. If you have problems, please open an issue.

**DO NOT USE THIS TOOLING IN PRODUCTION ENVIRONMENTS**
