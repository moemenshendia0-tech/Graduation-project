# Network Traffic SOC Dashboard

A read-only Flutter Web dashboard for the unified detection API. It shows candidate alerts for investigation; severity and confidence are separate fields, and neither indicates confirmed compromise.

## Run locally

The app expects the FastAPI service at http://127.0.0.1:8000 by default. Override it at build/run time with `API_BASE_URL`. Run Flutter commands from this directory on a local filesystem supported by the installed Flutter SDK. A Windows Flutter SDK may fail to write shader outputs when the project is accessed through a WSL UNC path; use a local Windows checkout/copy or a Linux filesystem instead. Release build output is generated under `build/web/` and should remain untracked.

With Flutter installed and available on `PATH`, install packages, run the development server, or create a release build:

```sh
flutter pub get
flutter run -d web-server --web-hostname 127.0.0.1 --web-port 8080 \
  --dart-define=API_BASE_URL=http://127.0.0.1:8000
flutter build web --release \
  --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

For `flutter run`, open http://127.0.0.1:8080 in a browser while the command remains running. For the release build, serve `build/web/` with a static web server. Start FastAPI separately and ensure the configured API URL is reachable from the browser. Replace the `API_BASE_URL` value when the API is hosted elsewhere.

## Tests and checks

Run these from `frontend/` with the installed Flutter SDK:

```sh
flutter pub get
dart format --output=none --set-exit-if-changed lib test
flutter analyze
flutter test
flutter build web --release --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

The only runtime package dependency used by the app is `http`; `material_ui` is also declared in `pubspec.yaml` and supplies Material shader assets. Flutter SDK test and lint packages are development dependencies. On 2026-11-21, `dart format --output=none --set-exit-if-changed lib test` reported 10 files and 0 changes, `flutter analyze` reported no issues, all 12 Flutter tests passed, and the release build succeeded in the native Windows QA copy. Browser integration against the live API and 129-alert dataset verified search, combined filters, sorting, pagination, alert details, and backend error/retry recovery. These checks were performed in the QA copy; they were not rerun as part of this documentation update. The earlier UNC `impellerc` failure was resolved by building from a native Windows filesystem.

## API usage

The client reads /health, /api/stats, /api/alerts, and /api/alerts/{alert_id}. Alert evidence is modeled and displayed as a string; it is not decoded as a JSON object. Alert IDs come from the backend response and remain response-only identifiers.