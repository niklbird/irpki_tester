# iRPKI Test
To run the test, compile Routinator with the included rpki-rs library.
Then create a repository by running the main of cure_pp. 
Install nginx and point it to the folder where the repository was created. By default, that is cure_pp/data/
Run Routinator with flag --irpki to use the iRPKI Notification file. Without the flag, it will run default Routinator. 