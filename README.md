# Download Manager

I wrote this sample code to explain how Boost.Beast can be used to download large files(I consider that > 100MB). It is one of those ways whereby we can download a certain chunk of data, flush it and download until we reach the end of file. This code is by no means efficient enough and may fail on servers that don't properly close SSL handshakes.
