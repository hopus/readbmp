# ReadBMP #

ReadBMP is a light c++ BMP (BGP Monitoring Protocol RFC7854) message collector and interpretor.

It is in early beta-development stage.

# Dependencies #
* [qiconn](https://github.com/jd-code/qiconn) is imported as a git submodule

# Usage #
there's yet no typical service script for maintaining the daemon operations.

it can be launched manually, for example :
```
./readbmp --maxmessage 10000 --connect=myrouter.somewhere.com:5001
```
will get the first 10000 BMP messages from the BMP source.

```
./readbmp --help
```
should give you the list of features and corresponding parameters.

### Building ###
the following will bring a default build :
```
git submodule init
git submodule update
( cd qiconn && autoall && ./configure )
autoall && ./configure
make all
```

---

> jd
