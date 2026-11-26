# Flutter Dashboard

Flutter Web client for the local historical alert API. It supports dashboard and Malware Intelligence navigation, filtering, sorting, paging, alert details/evidence, and CSV export from the API data. It does not provide live monitoring or PCAP upload.

## Setup

```bash
flutter pub get
flutter analyze
flutter test
flutter run -d web-server --web-hostname 127.0.0.1 --web-port 8080 \
  --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

`API_BASE_URL` is a compile-time define. The backend must be reachable from the browser and permit that loopback origin. Never put secrets in Dart defines or web assets. Bind the backend and frontend to loopback for local demonstration.

Release build:

```bash
flutter build web --release --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

Serve only the generated `build/web` directory with a local static server. For a Windows Flutter SDK, keep source and build output on a Windows-native filesystem if the SDK encounters WSL ACL limitations.
