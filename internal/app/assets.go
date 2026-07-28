package app

import "kiro-secops/internal/assets"

// payloadFS points to the embedded file system (payload/). It keeps the
// identifier used by the rest of the app package.
var payloadFS = assets.FS
