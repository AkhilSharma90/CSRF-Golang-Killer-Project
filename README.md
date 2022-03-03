# CSRF-Golang-Killer-Project
The project repository for my youtube series for CSRF token project with Golang. Use this for advanced requirements when you feel that JWT is not enough.
Based on a project we built for a client in 2019 - they needed something that made it slightly difficult to hack or steal customer data as it was a finance related app.
(it's a small scale finance app).

They're still using this same project structure (with many additions ofcourse) even after almost 4 years, they have more than 3,000 daily active users. This means it's stable
and great to use out of the box.

Please create "keys" folder at the root level and add a pair of private and public keys using RSA algo. the names of the keys should be - app.rsa and app.rsa.pub

The program won't run without putting the RSA keys as mentioned above :)
