import 'csv_download_stub.dart'
    if (dart.library.html) 'csv_download_web.dart'
    as platform;

void downloadCsv(String fileName, String content) =>
    platform.downloadCsv(fileName, content);
