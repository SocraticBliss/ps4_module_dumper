# ps4_module_dumper
Payload for dumping/decrypting all of the PS4 modules in one go

Still very much a POC, as I have only tested 1.01 and 5.05 so far

Still need to...
* Add user notifications
* Fix a few missing files
* Fix the files that are flagged as OS critical files

# Building
[PS4 Payload SDK](https://github.com/SocraticBliss/ps4-payload-sdk)

# Instructions
0) Compile the payload (make)
1) Plug in a USB flash drive to your PS4
2) Send the payload
3) After sending the payload, wait a minute or so and unplug the USB drive
4) Plug the USB into your PC, your PS4 firmware's version folder should be in there along with the modules

NOTE: You may have to show hidden files/show operating system files in order to see them (still working on this part...)
