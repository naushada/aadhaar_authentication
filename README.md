# aadhaar_authentication
Aadhaar Authentication OTP 1.6 and Auth 2.0 support
How to compile Aadhaar Authentication for Linux?
Answer: 1) It requires openSSL 1.1.0e, and install it in /usr/local/openssl-1.1.0e 
        2) Go to staging directory and execute following command
            2.1) ./configure
            2.2) make 
            2.3) make will generate the binary named "staging_uidai" in src folder
How to create distro?
Answer: 1) Go to staging folder and run this command - make dist, this will create the distribution in staging directory.


