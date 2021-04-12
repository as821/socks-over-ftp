# socks-over-ftp
SOCKS proxy over FTP(S)


current requirements:
    PyYAML
    
    PyNaCl


TODO

*   reimplement write/recv for both client and proxy --> currently spams the FTP server. want to read all packets that are available, then sleep rather than polling constantly
*   running with Firefox causes Listener class to crash (when Firefox is started after tunnel has been set up.  No issues if Firefox is started then tunnel is started.  Seems like Firefox opens/closes socket but I'm not really sure).
*   check/test heartbeat implementation (make sure works as expected.  Is completely untested.  Make sure proxy descriptor file is updated periodically and that client/proxy will terminate if other side is non-responsive)
*   check channel clean up --> seems like initial handshake files are not being deleted (probably just have to add a few lines here and there)
*   test channel with Chrome, maybe a few other browsers to make sure they all work ok
*   switch to using a YAML file for parameters (and have path to the YAML file passed as command line parameter, add a debug flag too)
*   ... not really sure, can probably start testing/analysis with it here I guess
