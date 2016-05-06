#include <allheaders.h>
#include <capi.h>

#ifdef WINDOWS
  #define NL "\r\n"
#elif POSIX
  #define NL "\n"
#else
  #error Unknown platform
#endif

#define error(fmt,...) printf("Error: "fmt NL,##__VA_ARGS__)


int main(int argc, char *argv[]) {
  TessBaseAPI* handle = NULL;
  PIX *img = NULL;
  char *text = NULL;
  int result = 1; // error

  handle = TessBaseAPICreate();
  if(TessBaseAPIInit3(handle, NULL, "eng")) {
    error("Failed to initialize tesseract api");
    goto EXIT;
  }

  img = pixRead("img.png");
  if(img == NULL) {
    error("pixRead failed");
    goto EXIT;
  }

  TessBaseAPISetImage2(handle, img);
  if(TessBaseAPIRecognize(handle, NULL)) {
    error("tesseract recognition failed");
    goto EXIT;
  }

  text = TessBaseAPIGetUTF8Text(handle);
  if(text == NULL) {
    error("tesseract failed to get text");
    goto EXIT;
  }
  fputs(text, stdout);
  result = 0;

 EXIT:
  if(text) {
    TessDeleteText(text);
  }

  if(img) {
    pixDestroy(&img);
  }

  if(handle) {
    TessBaseAPIEnd(handle);
    TessBaseAPIDelete(handle);
  }

  printf(result ? "FAIL" NL : "SUCCESS" NL);
  return result;
}






