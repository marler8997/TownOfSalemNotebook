@echo off

set LEPTONICA=D:\git\leptonica

set CC_OPT=
set CC_OPT=%CC_OPT% /DWINDOWS
set CC_OPT=%CC_OPT% /I %LEPTONICA%\leptonica\src
set CC_OPT=%CC_OPT% /I %LEPTONICA%\tesseract_master\api
set CC_OPT=%CC_OPT% /I %LEPTONICA%\tesseract_master\ccutil

set TESS_BIN=%LEPTONICA%\Release
set LIBS=
set LIBS=%LIBS% %TESS_BIN%\liblept.lib
set LIBS=%LIBS% %TESS_BIN%\libjpeg.lib
set LIBS=%LIBS% %TESS_BIN%\libpng.lib
set LIBS=%LIBS% %TESS_BIN%\libtiff.lib
set LIBS=%LIBS% %TESS_BIN%\giflib.lib
set LIBS=%LIBS% %TESS_BIN%\libtesseract.lib
set LIBS=%LIBS% %TESS_BIN%\zlib.lib
set LIBS=%LIBS% %TESS_BIN%\openjpeg.lib

cl %CC_OPT% %LIBS% OcrService.c
