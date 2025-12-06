# pside

TODO: stricter errors

when thread create -> insert new thread in threadmap with creator wait count (listen to clone with pid filter to get a new thread)
when mutex unlock -> wait untill match counter, check if mutex was contented if so, write coutner.
when mutex lock -> on start wait untill match counter and signal we waiting for mutex to be unlocked; 
                 |-> on return check if mutex got freed by someone if so copy counter to this thread counter. 

