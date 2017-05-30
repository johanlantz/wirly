# wirly
Wirly is a library that converts audio streams from wireshark traces into wav files. This might be useful for manual inspection of audio quality problems in VoIP systems. 

Wirly uses the media capabilities of the pjsip project and the supported codecs are:
* PCMA/PCMU
* GSM
* iLBC
* AMR-nb (wb to be added)
* Opus
* L16
* Speex
* G722

## Getting started Win32
Even though all the code is cross platform the easiest way to get started is to just use the available Visual Studio 2015 solution.
### 1. Fetch the submodules needed
```
git submodule init
git submodule update
```
### 2. Convert the Opus project
Unfortunately Visual Studio 2015 does not auto convert the VS2010 solution provided with the Opus project so before you open wirly.sln go to the third-party/codecs/opus/windows/win32/VS2010 folder and open opus.sln so Visual Studio converts it to 2015 format. You only have to do this once and after that you can open wirly.sln and everything will build out of the box.  
