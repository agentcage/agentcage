//! The shared engine: the current config (swapped atomically on reload,
//! with the last good config kept when a reload fails), the inspector
//! chain, the injector, and the per-host state every flow consults.
