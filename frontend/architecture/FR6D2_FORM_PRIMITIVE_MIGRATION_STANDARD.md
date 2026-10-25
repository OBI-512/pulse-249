# FR6-D2 Form Primitive Migration Standard

- Canonical low-level form controls live under `src/design-system/primitives`.
- `Button`, `Input`, `Select`, `Checkbox`, and `Textarea` are the allowed primitive owners.
- `unstyled` is a temporary visual-compatibility bridge for feature migrations; it preserves existing feature CSS while transferring markup/behavior ownership.
- New code must not introduce new raw controls in migrated files.
- FR6-D2 first migrates LoginPage, PasswordChangeRequired, and DeviceForm.
- Backend/API/database behavior is out of scope.
