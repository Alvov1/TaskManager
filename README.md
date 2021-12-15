# WinAPI-Qt-TaskManager
C ++ equivalent of Windows task manager, based on WinAPI functions. Allows to track files and processes in the operating system Windows.

The GUI is implemented using the Qt framework.

Program displays a list of processes running in the operating system and the following information about each of the processes: 
- Process name, PID;
- Process description;
- Path to the exe of the process;
- Name and PID of the parent process;
- Username of the owner of the process, SID;
- Process type (32x/64x);
- Using the DEP/ASLR technologies;
- List of using DLL's;

Program displays and allows modification of the following process safety information:
- Process integrity level;
- Process privileges;

![изображение](https://user-images.githubusercontent.com/39829227/146244269-6e1ae394-2cc7-41ca-8ca4-657c96d21fe0.png)
Image 1 - View running processes.

Program displays and allows to change the following information about any given file system object:
- Access control lists (ACL);
- Objects owner (by SID);
- Integrity level;

![изображение](https://user-images.githubusercontent.com/39829227/146244652-dbbf4807-3164-45d9-b263-9849e617a6b7.png)
Image 2 - View files in directory.


Database of the running processes can be saved in file in .json format.
